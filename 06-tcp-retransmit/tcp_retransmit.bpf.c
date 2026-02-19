// SPDX-License-Identifier: GPL-2.0
// ============================================================
// 06 - TCP 重传监控：BPF 内核态程序
//
// 知识点:
//   - tp/tcp/tcp_retransmit_skb：稳定的 TCP 重传 tracepoint（内核 4.15+）
//   - trace_event_raw_tcp_event_sk_skb：重传事件的上下文结构
//   - 从 skb 中提取 TCP/IP 四元组
//   - skb->sk 获取关联的 sock 结构
// ============================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "tcp_retransmit.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 重传次数统计（按连接四元组）
// key: src_ip XOR dst_ip XOR (sport << 16 | dport)
// value: 重传次数
struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct conn_key);
    __type(value, __u64);
} retransmit_stats SEC(".maps");

// ============================================================
// tracepoint: tcp/tcp_retransmit_skb
// ============================================================
// 注意：不同内核版本此 tracepoint 的字段有差异
// 内核 5.x 的 trace_event_raw_tcp_event_sk_skb 包含:
//   skbaddr, skaddr, state, sport, dport, family, saddr, daddr, saddr_v6, daddr_v6
SEC("tp/tcp/tcp_retransmit_skb")
int handle_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct retransmit_event *e;
    __u16 family = ctx->family;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type  = RETRANSMIT_SKB;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->af    = family;
    e->sport = ctx->sport;
    e->dport = ctx->dport;
    e->state = ctx->state;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    if (family == AF_INET) {
        e->saddr = ctx->saddr;
        e->daddr = ctx->daddr;
    } else {
        // IPv6 地址：saddr_v6, daddr_v6 是 __u8[4] 数组（4 个 u32）
        bpf_probe_read_kernel(e->saddr6, sizeof(e->saddr6), ctx->saddr_v6);
        bpf_probe_read_kernel(e->daddr6, sizeof(e->daddr6), ctx->daddr_v6);
    }

    // 更新连接重传统计（仅 IPv4）
    if (family == AF_INET) {
        struct conn_key key = {
            .saddr = ctx->saddr,
            .daddr = ctx->daddr,
            .sport = ctx->sport,
            .dport = ctx->dport,
        };
        __u64 *cnt = bpf_map_lookup_elem(&retransmit_stats, &key);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        } else {
            __u64 init = 1;
            bpf_map_update_elem(&retransmit_stats, &key, &init, BPF_NOEXIST);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// tracepoint: tcp/tcp_retransmit_synack
// SYN-ACK 重传（服务端重传三次握手中的 SYN-ACK）
// ============================================================
SEC("tp/tcp/tcp_retransmit_synack")
int handle_synack_retransmit(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
    struct retransmit_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type  = RETRANSMIT_SYNACK;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 从 request_sock 中读取地址
    struct sock *sk = (struct sock *)ctx->skaddr;
    e->af = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (e->af == AF_INET) {
        e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

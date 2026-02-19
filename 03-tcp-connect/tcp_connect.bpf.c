// SPDX-License-Identifier: GPL-2.0
// ============================================================
// 03 - TCP 连接监控：BPF 内核态程序
//
// 知识点:
//   - kprobe/kretprobe 组合：在函数入口存数据，返回时读结果
//   - BPF_MAP_TYPE_HASH：用 tid 作 key 传递 kprobe→kretprobe 的上下文
//   - BPF_KPROBE / BPF_KRETPROBE 宏：CO-RE 友好的 kprobe 写法
//   - BPF_CORE_READ：跨内核版本安全读取 sock 结构体字段
//   - skc_rcv_saddr / skc_daddr：IPv4 源/目标地址字段
//   - skc_addrpair / saddr6 / daddr6：IPv6 地址字段
// ============================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>  // BPF_KPROBE, BPF_KRETPROBE 宏
#include "tcp_connect.h"

char LICENSE[] SEC("license") = "GPL";

// ============================================================
// BPF Maps
// ============================================================

// Ring Buffer：向用户空间发送事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 临时存储：kprobe 入口时存 sock 指针，kretprobe 时取回
// key: tid (线程ID, 唯一标识一次系统调用)
// value: sock 指针
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct sock *);
} currsock SEC(".maps");

// ============================================================
// 辅助函数：填充 IPv4/IPv6 连接信息
// ============================================================
static __always_inline int fill_tcp_event_v4(struct tcp_event *e,
                                               struct sock *sk)
{
    e->af    = AF_INET;
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    // sport: skc_num 是本地端口，主机字节序
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    // dport: skc_dport 是目标端口，网络字节序，需要 bpf_ntohs 转换
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    return 0;
}

static __always_inline int fill_tcp_event_v6(struct tcp_event *e,
                                               struct sock *sk)
{
    e->af    = AF_INET6;
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    // IPv6 地址存在 skc_v6_rcv_saddr 和 skc_v6_daddr
    BPF_CORE_READ_INTO(e->saddr6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(e->daddr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    return 0;
}

// ============================================================
// IPv4: tcp_v4_connect
// ============================================================
// kprobe: 在 tcp_v4_connect 函数入口保存 sock 指针
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid(); // 低 32 位 = TID
    bpf_map_update_elem(&currsock, &tid, &sk, BPF_ANY);
    return 0;
}

// kretprobe: tcp_v4_connect 返回时，检查结果并发送事件
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct sock **skpp, *sk;
    struct tcp_event *e;
    struct task_struct *task;

    skpp = bpf_map_lookup_elem(&currsock, &tid);
    if (!skpp) return 0;

    sk = *skpp;
    bpf_map_delete_elem(&currsock, &tid);

    // 只记录成功的连接（ret == 0）
    if (ret != 0) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = TCP_EVENT_CONNECT;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    fill_tcp_event_v4(e, sk);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// IPv6: tcp_v6_connect
// ============================================================
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&currsock, &tid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct sock **skpp, *sk;
    struct tcp_event *e;
    struct task_struct *task;

    skpp = bpf_map_lookup_elem(&currsock, &tid);
    if (!skpp) return 0;

    sk = *skpp;
    bpf_map_delete_elem(&currsock, &tid);

    if (ret != 0) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = TCP_EVENT_CONNECT;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    fill_tcp_event_v6(e, sk);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// 监控 TCP ACCEPT（服务端接受连接）
// 使用 inet_csk_accept 的 kretprobe
// ============================================================
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *sk)
{
    struct tcp_event *e;
    struct task_struct *task;
    __u16 family;

    if (!sk) return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = TCP_EVENT_ACCEPT;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    if (family == AF_INET)
        fill_tcp_event_v4(e, sk);
    else
        fill_tcp_event_v6(e, sk);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

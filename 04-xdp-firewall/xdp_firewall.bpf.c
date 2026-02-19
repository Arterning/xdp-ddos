// SPDX-License-Identifier: GPL-2.0
// ============================================================
// 04 - XDP 流量统计 + 简易防火墙
//
// XDP（eXpress Data Path）是 eBPF 在网卡驱动层的钩子，
// 在 skb（socket buffer）分配之前处理数据包，性能极高。
//
// 知识点:
//   XDP 动作:
//     XDP_PASS  - 放行，进入正常网络栈
//     XDP_DROP  - 直接丢弃，不进入网络栈（比 iptables DROP 更早）
//     XDP_TX    - 从同一网卡转发回去（用于反射/负载均衡）
//     XDP_REDIRECT - 转发到其他网卡或 CPU
//     XDP_ABORTED - 程序错误，等同于 DROP（会计数）
//
//   数据包解析：
//     ctx->data 到 ctx->data_end 之间是原始以太网帧
//     每次访问前必须检查 ptr + header_size <= data_end（验证器要求）
//
//   BPF_MAP_TYPE_PERCPU_ARRAY：
//     每个 CPU 独立的数组，无需加锁，性能最优
//     最终统计时需要对所有 CPU 的值求和
//
//   BPF_MAP_TYPE_LRU_HASH：
//     LRU（最近最少使用）淘汰策略，适合存储黑名单（有限内存）
// ============================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>  // bpf_htons, bpf_ntohs
#include "xdp_firewall.h"

char LICENSE[] SEC("license") = "GPL";

// 以太网帧类型（网络字节序）
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

// IP 协议号
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP   17

// ============================================================
// BPF Maps
// ============================================================

// 每协议流量统计（PERCPU_ARRAY：每 CPU 独立计数，无锁，高性能）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PROTO_MAX);
    __type(key, __u32);
    __type(value, struct proto_stats);
} stats SEC(".maps");

// IP 黑名单（LRU_HASH：自动淘汰最旧的条目）
// key: IPv4 源地址（网络字节序）
// value: 1 = 封锁
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocklist SEC(".maps");

// ============================================================
// 辅助函数：更新统计计数
// ============================================================
static __always_inline void update_stats(__u32 proto_idx, __u32 pkt_len)
{
    struct proto_stats *s = bpf_map_lookup_elem(&stats, &proto_idx);
    if (s) {
        // __sync_fetch_and_add 是原子操作，但在 PERCPU_ARRAY 中
        // 每个 CPU 有独立副本，实际上不需要原子操作
        // 这里使用是为了满足 BPF 验证器的要求（防止竞态）
        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
    }
}

// ============================================================
// XDP 主程序
// ============================================================
// SEC("xdp") 将此程序挂载为 XDP 类型
// struct xdp_md 是 XDP 上下文，包含数据包指针
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    // ctx->data 和 ctx->data_end 是偏移量，需转换为指针
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len  = data_end - data;

    // ── 第一层：解析以太网头 ───────────────────────────────
    struct ethhdr *eth = data;

    // 关键：边界检查！
    // 每次访问数据包内容之前，必须验证不会越界
    // 否则 BPF 验证器会拒绝程序加载
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 只处理 IPv4（教学简化，生产环境应同时处理 IPv6）
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto pass_other;

    // ── 第二层：解析 IP 头 ────────────────────────────────
    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // IP 头长度是动态的（options 字段），ihl * 4 字节
    // 最小 20 字节（ihl=5），最大 60 字节（ihl=15）
    if (iph->ihl < 5)
        return XDP_PASS;

    // ── 黑名单检查 ────────────────────────────────────────
    __u32 src_ip = iph->saddr; // 网络字节序
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked && *blocked) {
        // 在黑名单中，直接丢弃（不进入任何网络栈处理）
        update_stats(PROTO_OTHER, pkt_len); // 可以单独统计被封锁的包
        return XDP_DROP;
    }

    // ── 协议分类统计 ─────────────────────────────────────
    __u32 proto_idx;
    switch (iph->protocol) {
    case IPPROTO_TCP:
        proto_idx = PROTO_TCP;
        break;
    case IPPROTO_UDP:
        proto_idx = PROTO_UDP;
        break;
    case IPPROTO_ICMP:
        proto_idx = PROTO_ICMP;
        break;
    default:
        proto_idx = PROTO_OTHER;
        break;
    }
    update_stats(proto_idx, pkt_len);
    return XDP_PASS;

pass_other:
    update_stats(PROTO_OTHER, pkt_len);
    return XDP_PASS;
}

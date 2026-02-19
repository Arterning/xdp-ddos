// SPDX-License-Identifier: GPL-2.0
// ============================================================
// 07 - XDP 毫秒级 DDoS 防护：BPF 内核态程序
//
// 为什么 XDP 能实现毫秒级响应：
//   传统防护：包 → 网卡中断 → 内存复制 → skb 分配 → 网络栈 → iptables → 丢弃
//   XDP 防护：包 → 网卡 RX 队列 → XDP 程序（在驱动层直接丢弃）
//
//   XDP 在 skb 分配之前运行，完全绕过 Linux 网络栈
//   单核可达 10+ Mpps（百万包/秒），响应时间 < 100 微秒
//
// 防护机制：
//   1. 黑名单检查（O(1)，LRU hash）
//   2. 令牌桶限速（per-IP，LRU hash）
//   3. SYN Flood 检测（滑动窗口计数）
//   4. 自动拉黑超限 IP
//   5. 通过 Ring Buffer 通知用户空间
//
// 数据包解析流程：
//   以太网帧 → IP 头 → TCP/UDP 头
//   每步都需要边界检查（BPF 验证器要求）
// ============================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_ddos.h"

char LICENSE[] SEC("license") = "GPL";

// 以太网/IP/TCP 常量
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define TCP_FLAG_SYN 0x02

// ============================================================
// BPF Maps
// ============================================================

// 配置（用户空间可动态修改）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ddos_config);
} cfg_map SEC(".maps");

// IP 黑名单（LRU_HASH：自动淘汰旧条目，节省内存）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 源地址（网络字节序）
    __type(value, struct ddos_blacklist_entry);
} blacklist SEC(".maps");

// 每 IP 令牌桶状态（LRU_HASH：自动清理不活跃 IP）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct ddos_token_bucket);
} buckets SEC(".maps");

// 每 IP SYN 计数器
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct syn_counter);
} syn_counters SEC(".maps");

// 全局统计（PERCPU：每 CPU 独立计数，无锁）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Ring Buffer：通知用户空间有 IP 被拉黑
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

// ============================================================
// 辅助函数
// ============================================================

static __always_inline void inc_stats(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

// 获取配置（带默认值兜底）
static __always_inline struct ddos_config get_config(void)
{
    __u32 zero = 0;
    struct ddos_config *cfg = bpf_map_lookup_elem(&cfg_map, &zero);
    if (cfg) return *cfg;

    // 默认配置
    struct ddos_config def = {
        .max_pps           = DEFAULT_MAX_PPS,
        .burst_size        = DEFAULT_BURST_SIZE,
        .syn_threshold     = DEFAULT_SYN_THRESHOLD,
        .blacklist_threshold = DEFAULT_BLACKLIST_THRESH,
        .blacklist_duration_s = DEFAULT_BLACKLIST_DUR_S,
    };
    return def;
}

// 令牌桶：检查并消耗令牌
// 返回 true = 允许，false = 超速丢弃
static __always_inline bool token_bucket_allow(__u32 src_ip, __u64 now_ns,
                                                struct ddos_config *cfg)
{
    struct ddos_token_bucket *tb = bpf_map_lookup_elem(&buckets, &src_ip);

    if (!tb) {
        // 新 IP：初始化令牌桶（满桶）
        struct ddos_token_bucket new_tb = {
            .tokens         = cfg->burst_size,
            .last_refill_ns = now_ns,
            .pass_packets   = 1,
            .drop_packets   = 0,
            .rate_limit_hits = 0,
        };
        bpf_map_update_elem(&buckets, &src_ip, &new_tb, BPF_ANY);
        return true;
    }

    // 计算本次应补充的令牌数
    // 公式：new_tokens = elapsed_ns * max_pps / 1e9
    // 为防止溢出，先将 elapsed 限制在 burst_time 内
    // burst_time_ns = burst_size * 1e9 / max_pps
    __u64 elapsed_ns = now_ns - tb->last_refill_ns;

    // 计算补充令牌（整数运算，避免浮点）
    // elapsed_ns * max_pps 可能溢出（u64 max = 18.4e18）
    // 安全范围：elapsed < 1e9 且 max_pps < 1e7 → 最大 1e16，安全
    __u64 new_tokens = 0;
    if (elapsed_ns > 1000000000ULL) {
        // 超过 1 秒，直接填满
        new_tokens = cfg->burst_size;
        elapsed_ns = 0; // 重置计时
    } else {
        new_tokens = elapsed_ns * cfg->max_pps / 1000000000ULL;
    }

    tb->tokens += new_tokens;
    tb->last_refill_ns += elapsed_ns; // 不用 now_ns，避免累积误差

    // 限制令牌上限（桶容量）
    if (tb->tokens > cfg->burst_size)
        tb->tokens = cfg->burst_size;

    // 消耗令牌
    if (tb->tokens >= 1) {
        tb->tokens--;
        tb->pass_packets++;
        return true; // 允许通过
    }

    // 令牌耗尽，丢包
    tb->drop_packets++;
    tb->rate_limit_hits++;
    return false;
}

// SYN Flood 检测：滑动窗口计数
// 返回 true = 检测到 SYN Flood
static __always_inline bool syn_flood_check(__u32 src_ip, __u64 now_ns,
                                             struct ddos_config *cfg)
{
    // 窗口大小：1 秒
    #define SYN_WINDOW_NS 1000000000ULL

    struct syn_counter *sc = bpf_map_lookup_elem(&syn_counters, &src_ip);

    if (!sc) {
        struct syn_counter new_sc = {
            .window_start_ns = now_ns,
            .syn_count       = 1,
        };
        bpf_map_update_elem(&syn_counters, &src_ip, &new_sc, BPF_ANY);
        return false;
    }

    // 判断是否进入新窗口（超过 1 秒）
    if (now_ns - sc->window_start_ns > SYN_WINDOW_NS) {
        // 新窗口，重置计数
        sc->window_start_ns = now_ns;
        sc->syn_count = 1;
        return false;
    }

    sc->syn_count++;

    // 超过 SYN 阈值 → SYN Flood！
    return sc->syn_count > cfg->syn_threshold;
}

// 将 IP 加入黑名单并通知用户空间
static __always_inline void blacklist_ip(__u32 src_ip, __u64 now_ns,
                                          __u8 reason, __u64 drop_count)
{
    struct ddos_blacklist_entry entry = {
        .added_ns   = now_ns,
        .drop_count = drop_count,
        .reason     = reason,
    };
    bpf_map_update_elem(&blacklist, &src_ip, &entry, BPF_ANY);

    // 通知用户空间
    struct blacklist_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->src_ip     = src_ip;
        ev->reason     = reason;
        ev->drop_count = drop_count;
        bpf_ringbuf_submit(ev, 0);
    }
}

// ============================================================
// XDP 主程序
// ============================================================
SEC("xdp")
int xdp_ddos_protect(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── 解析以太网头 ──────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 只处理 IPv4（IPv6 DDoS 防护可类似扩展）
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // ── 解析 IP 头 ────────────────────────────────────────
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->ihl < 5)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 now_ns = bpf_ktime_get_ns();

    // ── 第一道防线：黑名单检查（O(1) hash lookup）────────
    struct ddos_blacklist_entry *bl = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (bl) {
        // 检查黑名单是否过期
        struct ddos_config cfg = get_config();
        if (cfg.blacklist_duration_s > 0) {
            __u64 expire_ns = bl->added_ns +
                              ((__u64)cfg.blacklist_duration_s * 1000000000ULL);
            if (now_ns > expire_ns) {
                // 黑名单已过期，解封
                bpf_map_delete_elem(&blacklist, &src_ip);
                goto check_rate;
            }
        }
        // 黑名单有效，直接丢弃
        bl->drop_count++;
        inc_stats(STATS_BLACKLIST);
        return XDP_DROP;
    }

check_rate:;
    struct ddos_config cfg = get_config();

    // ── 第二道防线：SYN Flood 检测 ────────────────────────
    if (iph->protocol == IPPROTO_TCP) {
        // 计算 TCP 头偏移（IP 头可能有 options）
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) <= data_end) {
            if (tcph->syn && !tcph->ack) {
                // 纯 SYN 包（三次握手第一步）
                if (syn_flood_check(src_ip, now_ns, &cfg)) {
                    // SYN Flood！立即拉黑
                    blacklist_ip(src_ip, now_ns, BL_REASON_SYN_FLOOD, 0);
                    inc_stats(STATS_DROP);
                    return XDP_DROP;
                }
            }
        }
    }

    // ── 第三道防线：令牌桶限速 ────────────────────────────
    if (!token_bucket_allow(src_ip, now_ns, &cfg)) {
        // 被限速
        inc_stats(STATS_DROP);

        // 检查是否需要自动拉黑
        struct ddos_token_bucket *tb = bpf_map_lookup_elem(&buckets, &src_ip);
        if (tb && tb->rate_limit_hits >= cfg.blacklist_threshold) {
            blacklist_ip(src_ip, now_ns, BL_REASON_RATE_LIMIT,
                         tb->drop_packets);
        }

        return XDP_DROP;
    }

    // 通过所有检查，放行
    inc_stats(STATS_PASS);
    return XDP_PASS;
}

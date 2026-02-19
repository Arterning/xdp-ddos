#ifndef __XDP_DDOS_H
#define __XDP_DDOS_H

// ============================================================
// XDP DDoS 防护共享头文件
//
// 设计思路：令牌桶（Token Bucket）算法
//
//   每个源 IP 维护一个令牌桶：
//     - 桶容量 = burst_size（允许的突发包数）
//     - 令牌补充速率 = max_pps（每秒最多允许通过的包数）
//     - 每收到一个包消耗 1 个令牌
//     - 令牌不足时丢包
//
//   SYN Flood 检测：
//     - 在滑动时间窗口内统计 SYN 包数量
//     - 超过阈值触发自动封锁
//
//   IP 自动拉黑：
//     - 被限速超过 blacklist_threshold 次 → 自动加入黑名单
//     - 黑名单 IP 的所有包直接丢弃（零检测开销）
// ============================================================

// 配置结构（存在 config map 中，用户空间可动态修改）
struct ddos_config {
    __u32 max_pps;              // 每 IP 最大包速率（包/秒）
    __u32 burst_size;           // 令牌桶容量（允许的突发包数）
    __u32 syn_threshold;        // SYN 包速率阈值（超过即触发封锁）
    __u32 blacklist_threshold;  // 被限速多少次后自动拉黑
    __u32 blacklist_duration_s; // 黑名单持续时间（秒，0=永久）
};

// 默认配置
#define DEFAULT_MAX_PPS           1000    // 每 IP 每秒 1000 包
#define DEFAULT_BURST_SIZE        200     // 允许 200 包的突发
#define DEFAULT_SYN_THRESHOLD     500     // 每秒 SYN 包超过 500 触发封锁
#define DEFAULT_BLACKLIST_THRESH  10      // 被限速 10 次后拉黑
#define DEFAULT_BLACKLIST_DUR_S   300     // 黑名单持续 5 分钟

// 每个 IP 的令牌桶状态
struct token_bucket {
    __u64 tokens;           // 当前令牌数量
    __u64 last_refill_ns;   // 上次补充令牌的时间（纳秒）
    __u64 pass_packets;     // 通过的包数
    __u64 drop_packets;     // 丢弃的包数
    __u32 rate_limit_hits;  // 被限速次数（用于触发自动拉黑）
};

// SYN 计数器（滑动时间窗口）
struct syn_counter {
    __u64 window_start_ns;  // 当前统计窗口开始时间
    __u64 syn_count;        // 当前窗口内的 SYN 包数量
};

// 黑名单条目
struct blacklist_entry {
    __u64 added_ns;         // 加入黑名单的时间
    __u64 drop_count;       // 累计丢包数
    __u8  reason;           // 原因（1=限速, 2=SYN flood）
};
#define BL_REASON_RATE_LIMIT 1
#define BL_REASON_SYN_FLOOD  2

// 全局统计（索引）
#define STATS_PASS       0   // 通过的包数
#define STATS_DROP       1   // 丢弃的包数（被限速）
#define STATS_BLACKLIST  2   // 黑名单丢包数
#define STATS_MAX        3

// 事件：IP 被加入黑名单（通知用户空间）
struct blacklist_event {
    __u32 src_ip;
    __u8  reason;
    __u8  pad[3];
    __u64 drop_count;
};

#endif /* __XDP_DDOS_H */

// SPDX-License-Identifier: GPL-2.0
// ============================================================
// 05 - 函数耗时统计：BPF 内核态程序
//
// 知识点:
//   - kprobe + kretprobe 配对：入口记录时间，出口计算差值
//   - bpf_ktime_get_ns()：内核单调时钟（纳秒），用于精确计时
//   - log2 直方图：在 BPF 中手动计算对数桶
//   - PERCPU_ARRAY + atomic add：高性能计数器
//   - BPF_MAP_TYPE_HASH 用 tid 传递 kprobe→kretprobe 的时间戳
//
// 默认监控函数: vfs_read（VFS 层读取，覆盖所有文件 read 调用）
// 修改 kprobe/kretprobe 的 SEC 注解可以监控其他函数
// ============================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "func_latency.h"

char LICENSE[] SEC("license") = "GPL";

// ============================================================
// BPF Maps
// ============================================================

// 记录每个线程进入 vfs_read 的时间戳
// key: tid (u32)  value: 时间戳 (ns)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start_ts SEC(".maps");

// log2 直方图：slot[i] = 耗时在 [2^i ns, 2^(i+1) ns) 的调用次数
// 例: slot[10] 对应 1024ns ~ 2047ns（约 1 微秒）
//     slot[20] 对应 ~1ms
//     slot[30] 对应 ~1s
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} histogram SEC(".maps");

// 总调用次数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} total_calls SEC(".maps");

// Ring Buffer：发送单次调用事件（用于显示最慢的几次调用）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 慢调用阈值：超过此值才发送事件到 ring buffer（纳秒）
// 默认 1ms，可通过修改此值调整
#define SLOW_THRESHOLD_NS (1 * 1000 * 1000ULL)

// ============================================================
// 辅助函数：计算 log2（用于确定直方图桶号）
// ============================================================
// BPF 验证器要求循环必须可被证明会终止（bounded loop）
// 或者使用 __always_inline 展开的条件判断
static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 r = 0;

    // 使用位移判断代替循环（BPF 验证器友好）
    // 逐步缩小范围，类似二分查找
    if (v >= (1ULL << 32)) { r += 32; v >>= 32; }
    if (v >= (1ULL << 16)) { r += 16; v >>= 16; }
    if (v >= (1ULL << 8))  { r +=  8; v >>=  8; }
    if (v >= (1ULL << 4))  { r +=  4; v >>=  4; }
    if (v >= (1ULL << 2))  { r +=  2; v >>=  2; }
    if (v >= (1ULL << 1))  { r +=  1;            }

    return r;
}

// ============================================================
// kprobe: vfs_read 入口
// ============================================================
SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ts  = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_ts, &tid, &ts, BPF_ANY);
    return 0;
}

// ============================================================
// kretprobe: vfs_read 返回
// ============================================================
SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(vfs_read_exit, ssize_t ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *ts_ptr, delta_ns;
    __u32 slot, zero = 0;
    __u64 *cnt;

    ts_ptr = bpf_map_lookup_elem(&start_ts, &tid);
    if (!ts_ptr)
        return 0; // 没有对应的入口记录

    delta_ns = bpf_ktime_get_ns() - *ts_ptr;
    bpf_map_delete_elem(&start_ts, &tid);

    // 忽略失败的调用（ret < 0）
    if (ret < 0)
        return 0;

    // ① 计算 log2 桶号并更新直方图
    slot = log2_u64(delta_ns);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    cnt = bpf_map_lookup_elem(&histogram, &slot);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    // ② 更新总调用次数
    cnt = bpf_map_lookup_elem(&total_calls, &zero);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    // ③ 慢调用：超过阈值则发送详细事件
    if (delta_ns > SLOW_THRESHOLD_NS) {
        struct latency_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->duration_ns = delta_ns;
            e->pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
    }

    return 0;
}

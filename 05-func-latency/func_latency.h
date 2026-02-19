#ifndef __FUNC_LATENCY_H
#define __FUNC_LATENCY_H

#define TASK_COMM_LEN  16
#define MAX_SLOTS      26   // log2 直方图桶数：26 个桶覆盖 1ns ~ 64s

// 用于 kprobe → kretprobe 传递上下文的结构
struct start_key {
    __u32 tid;    // 线程 ID
};

// 单次调用的统计事件（通过 ring buffer 发送给用户空间）
struct latency_event {
    __u64 duration_ns;          // 本次调用耗时（纳秒）
    __u32 pid;
    char  comm[TASK_COMM_LEN];
};

// 用户空间读取直方图用的结构
// 直方图存在 BPF_MAP_TYPE_ARRAY 中，每个 slot 对应 2^n ns 的耗时范围
// slot[i] 表示耗时在 [2^i, 2^(i+1)) ns 的调用次数
struct hist_key {
    __u32 slot;  // 桶编号（log2）
};

#endif /* __FUNC_LATENCY_H */

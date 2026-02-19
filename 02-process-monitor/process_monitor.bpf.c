// SPDX-License-Identifier: GPL-2.0
// ============================================================
// 02 - 进程监控：BPF 内核态程序
//
// 知识点:
//   - 多 tracepoint 挂载：一个 BPF 对象可以包含多个程序
//   - BPF_MAP_TYPE_HASH：用于保存进程创建时间（pid → start_ns）
//   - trace_event_raw_sched_process_exec：exec tracepoint 上下文
//   - trace_event_raw_sched_process_fork：fork tracepoint 上下文
//   - __data_loc 字段：tracepoint 中动态长度字符串的读取方式
// ============================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "process_monitor.h"

char LICENSE[] SEC("license") = "GPL";

// ============================================================
// BPF Maps
// ============================================================

// Ring Buffer：向用户空间发送事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Hash Map：记录每个进程的创建时间，用于计算生命周期
// key: pid (u32)  value: 创建时间戳 (ns)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} start_time SEC(".maps");

// ============================================================
// 辅助函数：填充通用事件字段
// ============================================================
static __always_inline void fill_common(struct proc_event *e,
                                         enum event_type type)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->type = type;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

// ============================================================
// tracepoint: sched/sched_process_exec
// 触发时机：execve() 系统调用成功完成后
// 此时新程序已经替换了原来的地址空间
// ============================================================
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct proc_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_EXEC);
    e->child_pid = 0;
    e->exit_code = 0;
    e->duration_ns = 0;

    // 读取 filename 字段
    // trace_event_raw_sched_process_exec 中 filename 是 __data_loc 类型
    // __data_loc 是内核 tracepoint 中存储动态长度字符串的方式
    // 格式：低16位 = 字符串相对于 ctx 的偏移，高16位 = 长度
    // 通过 & 0xffff 取偏移，加上 ctx 基地址即得到字符串指针
    unsigned int filename_off = ctx->__data_loc_filename & 0xffff;
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
                              (void *)ctx + filename_off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// tracepoint: sched/sched_process_fork
// 触发时机：fork/clone 系统调用完成，子进程创建后
// ============================================================
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct proc_event *e;
    __u32 child_pid = ctx->child_pid;
    __u64 ts = bpf_ktime_get_ns();

    // 记录子进程的创建时间（供 EXIT 时计算生命周期）
    bpf_map_update_elem(&start_time, &child_pid, &ts, BPF_ANY);

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_FORK);
    e->child_pid = child_pid;
    e->exit_code = 0;
    e->duration_ns = 0;
    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// tracepoint: sched/sched_process_exit
// 触发时机：进程退出时（do_exit 函数内）
// ============================================================
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct proc_event *e;
    struct task_struct *task;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *start_ns;
    __u64 duration_ns = 0;

    // 只监控主线程退出（避免线程退出产生大量噪音）
    // 当 PID == TID 时才是主线程（进程本身）退出
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (pid != tid) return 0;

    // 查找进程创建时间，计算生命周期
    start_ns = bpf_map_lookup_elem(&start_time, &pid);
    if (start_ns) {
        duration_ns = bpf_ktime_get_ns() - *start_ns;
        bpf_map_delete_elem(&start_time, &pid);
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_EXIT);
    e->child_pid = 0;
    e->duration_ns = duration_ns;
    e->filename[0] = '\0';

    // 读取退出码：从 task_struct->exit_code 获取
    task = (struct task_struct *)bpf_get_current_task();
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

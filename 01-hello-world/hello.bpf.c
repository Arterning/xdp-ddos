// SPDX-License-Identifier: GPL-2.0
// ============================================================
// 01 - Hello World：eBPF 内核态程序（libbpf C 版本）
//
// 对应 BPFTrace 版: hello.bt
//
// 知识点:
//   SEC()               - 指定 ELF section，libbpf 根据名称决定挂载方式
//   BPF_MAP_TYPE_RINGBUF - Ring Buffer，高效的内核→用户单向数据通道
//   bpf_ringbuf_reserve  - 预留 ring buffer 空间（原子操作）
//   bpf_ringbuf_submit   - 提交数据（唤醒用户空间 poll）
//   bpf_get_current_pid_tgid - 获取 PID/TGID（高32位=TGID=PID）
//   bpf_get_current_comm     - 获取当前进程名
//   bpf_probe_read_user_str  - 安全读取用户空间字符串
//   BPF_CORE_READ            - CO-RE 安全读取内核结构体字段
// ============================================================

#include "vmlinux.h"             // 由 bpftool 从运行内核生成，包含所有内核类型定义
#include <bpf/bpf_helpers.h>    // BPF helper 函数（bpf_printk, bpf_map_lookup_elem 等）
#include <bpf/bpf_core_read.h>  // CO-RE 宏（BPF_CORE_READ, BPF_CORE_READ_STR_INTO 等）
#include "hello.h"              // 共享数据结构（struct event）

// BPF 程序必须声明 License
// "GPL" 才能使用完整的 helper 函数集（部分 helper 需要 GPL 兼容许可）
char LICENSE[] SEC("license") = "GPL";

// ============================================================
// BPF Map：Ring Buffer
// ============================================================
// Ring Buffer 是 Linux 5.8 引入的高效 BPF map
// 特点：
//   - 固定大小的环形内存，内核写入，用户空间读取
//   - 无需 per-CPU 实例，节省内存
//   - 支持可变大小记录
//   - 用户空间通过 epoll 等待事件（不需要轮询）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 缓冲区大小：256KB（必须是 2 的幂次）
} rb SEC(".maps");

// ============================================================
// BPF 程序入口
// ============================================================
// SEC("tp/syscalls/sys_enter_execve")：
//   "tp"        = tracepoint
//   "syscalls"  = tracepoint 分类（对应 /sys/kernel/debug/tracing/events/syscalls/）
//   "sys_enter_execve" = 具体的 tracepoint 名称（execve 系统调用入口）
//
// 参数类型 struct trace_event_raw_sys_enter 来自 vmlinux.h
// 其中 ctx->args[0..5] 对应系统调用的6个参数
// execve(const char *filename, char *const argv[], char *const envp[])
//   args[0] = filename, args[1] = argv, args[2] = envp
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // ① 在 Ring Buffer 中原子地预留一块内存
    // 如果 ring buffer 满了，返回 NULL（事件丢失）
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // ② 获取 PID
    // bpf_get_current_pid_tgid() 返回 u64：高32位=TGID（进程ID），低32位=TID（线程ID）
    // 对单线程进程：TGID == PID
    e->pid = bpf_get_current_pid_tgid() >> 32;

    // ③ 获取父进程 PID
    // bpf_get_current_task() 返回当前 task_struct 指针
    // BPF_CORE_READ 使用 BTF 信息安全读取字段，跨内核版本兼容
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // ④ 获取当前进程名（调用 execve 的进程，即父进程）
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // ⑤ 读取 execve 的第一个参数：要执行的文件路径
    // ctx->args[0] 是用户空间指针，必须用 bpf_probe_read_user_str 安全读取
    // 直接解引用用户空间指针会导致 BPF 验证器拒绝
    bpf_probe_read_user_str(e->filename, sizeof(e->filename),
                            (const char *)ctx->args[0]);

    // ⑥ 提交事件，通知用户空间可以消费
    bpf_ringbuf_submit(e, 0);

    return 0;
}

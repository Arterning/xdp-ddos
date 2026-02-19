// ============================================================
// 01 - Hello World：用户空间程序
//
// 功能：加载 BPF 程序，接收并打印 execve 事件
//
// 知识点:
//   xxx_bpf__open_and_load() - 骨架 API：打开 BPF 对象并加载到内核
//   xxx_bpf__attach()        - 骨架 API：挂载所有 BPF 程序
//   ring_buffer__new()       - 创建 ring buffer 消费者
//   ring_buffer__poll()      - 等待并处理 ring buffer 中的事件
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"  // 由 bpftool gen skeleton 自动生成
#include "hello.h"

// 控制主循环退出的标志（volatile 防止编译器优化）
static volatile int exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

// ============================================================
// Ring Buffer 回调函数
// 每当内核提交一个事件，libbpf 就调用这个函数
// ============================================================
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    char ts[16];
    time_t t;
    struct tm *tm;

    // 格式化当前时间
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-8s %-7d %-7d %-16s %s\n",
           ts, e->pid, e->ppid, e->comm, e->filename);

    return 0;
}

// 设置 libbpf 日志级别（调试时可改为 LIBBPF_DEBUG）
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0; // 屏蔽调试级别日志
    return vfprintf(stderr, format, args);
}

int main(void)
{
    struct hello_bpf *skel;  // BPF 骨架对象
    struct ring_buffer *rb;  // Ring Buffer 消费者
    int err;

    // 设置 libbpf 回调
    libbpf_set_print(libbpf_print_fn);

    // ① 打开、加载并验证 BPF 程序
    // open_and_load 内部流程：
    //   - 读取嵌入的 BPF ELF 字节码
    //   - 解析 maps 和 programs
    //   - 通过 bpf() 系统调用将 BPF 程序加载到内核
    //   - 内核 BPF 验证器检查程序安全性
    skel = hello_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] 无法加载 BPF 程序\n");
        return 1;
    }

    // ② 挂载 BPF 程序到对应的 tracepoint
    // libbpf 根据 SEC() 注解自动识别挂载类型
    err = hello_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] 无法挂载 BPF 程序: %d\n", err);
        goto cleanup;
    }

    // ③ 创建 Ring Buffer 消费者
    // 参数：map fd，回调函数，上下文，选项
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] 无法创建 ring buffer\n");
        err = -1;
        goto cleanup;
    }

    // 注册信号处理（Ctrl+C 干净退出）
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] eBPF Hello World 启动，监听 execve 调用...\n");
    printf("[+] 按 Ctrl+C 退出\n\n");
    printf("%-8s %-7s %-7s %-16s %s\n", "TIME", "PID", "PPID", "COMM", "FILENAME");
    printf("%-8s %-7s %-7s %-16s %s\n",
           "--------", "-------", "-------", "----------------", "--------");

    // ④ 主循环：轮询 ring buffer
    while (!exiting) {
        // ring_buffer__poll 阻塞最多 100ms 等待事件
        // 有事件时立即调用 handle_event 回调
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "[-] ring buffer poll 错误: %d\n", err);
            break;
        }
    }

    printf("\n[*] 退出\n");
    ring_buffer__free(rb);

cleanup:
    hello_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

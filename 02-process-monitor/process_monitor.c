// ============================================================
// 02 - 进程监控：用户空间程序
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "process_monitor.skel.h"
#include "process_monitor.h"

static volatile int exiting = 0;

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct proc_event *e = data;
    char ts[16];
    time_t t;
    struct tm *tm;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    switch (e->type) {
    case EVENT_EXEC:
        printf("%-8s \033[32mEXEC \033[0m pid=%-6d ppid=%-6d comm=%-16s file=%s\n",
               ts, e->pid, e->ppid, e->comm, e->filename);
        break;

    case EVENT_FORK:
        printf("%-8s \033[33mFORK \033[0m pid=%-6d ppid=%-6d comm=%-16s child_pid=%d\n",
               ts, e->pid, e->ppid, e->comm, e->child_pid);
        break;

    case EVENT_EXIT:
        printf("%-8s \033[31mEXIT \033[0m pid=%-6d ppid=%-6d comm=%-16s exit=%d duration=%.3fms\n",
               ts, e->pid, e->ppid, e->comm, e->exit_code,
               e->duration_ns / 1e6);
        break;

    default:
        break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct process_monitor_bpf *skel;
    struct ring_buffer *rb;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = process_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] 无法加载 BPF 程序\n");
        return 1;
    }

    err = process_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] 无法挂载 BPF 程序\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] 无法创建 ring buffer\n");
        err = -1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] 进程监控启动（监控 exec/fork/exit）\n");
    printf("[+] 按 Ctrl+C 退出\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "[-] ring buffer poll 错误: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
cleanup:
    process_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

// ============================================================
// 06 - TCP 重传监控：用户空间程序
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "tcp_retransmit.skel.h"
#include "tcp_retransmit.h"

static volatile int exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

// TCP 状态名称
static const char *tcp_state_str(int state)
{
    static const char *states[] = {
        "", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
        "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
        "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING",
    };
    if (state >= 0 && state < (int)(sizeof(states)/sizeof(*states)))
        return states[state];
    return "UNKNOWN";
}

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct retransmit_event *e = data;
    char ts[16], src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    time_t t;
    struct tm *tm;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (e->af == AF_INET) {
        inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));
    } else {
        inet_ntop(AF_INET6, e->saddr6, src, sizeof(src));
        inet_ntop(AF_INET6, e->daddr6, dst, sizeof(dst));
    }

    const char *type = (e->type == RETRANSMIT_SYNACK) ?
                       "\033[33mSYNACK\033[0m" : "\033[31mRETRAN\033[0m";

    printf("%-8s %s pid=%-6d %-6s %s:%-5d → %s:%-5d [state=%s]\n",
           ts, type, e->pid, e->comm,
           src, e->sport, dst, e->dport,
           tcp_state_str(e->state));

    return 0;
}

int main(void)
{
    struct tcp_retransmit_bpf *skel;
    struct ring_buffer *rb;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = tcp_retransmit_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] 无法加载 BPF 程序\n");
        return 1;
    }

    err = tcp_retransmit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] 无法挂载 BPF 程序\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) { err = -1; goto cleanup; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] TCP 重传监控启动\n");
    printf("[+] 按 Ctrl+C 退出\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

    ring_buffer__free(rb);
cleanup:
    tcp_retransmit_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

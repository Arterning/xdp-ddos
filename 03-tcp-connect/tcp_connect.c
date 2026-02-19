// ============================================================
// 03 - TCP 连接监控：用户空间程序
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "tcp_connect.skel.h"
#include "tcp_connect.h"

static volatile int exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

// 将 IPv4/IPv6 地址格式化为字符串
static void format_addr(char *buf, size_t len, __u16 af,
                         __u32 addr4, __u8 *addr6)
{
    if (af == AF_INET) {
        inet_ntop(AF_INET, &addr4, buf, len);
    } else {
        inet_ntop(AF_INET6, addr6, buf, len);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct tcp_event *e = data;
    char ts[16], src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    const char *type_str;
    time_t t;
    struct tm *tm;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    format_addr(src, sizeof(src), e->af, e->saddr, (void *)e->saddr6);
    format_addr(dst, sizeof(dst), e->af, e->daddr, (void *)e->daddr6);

    switch (e->type) {
    case TCP_EVENT_CONNECT:
        type_str = "\033[32mCONNECT\033[0m";
        break;
    case TCP_EVENT_ACCEPT:
        type_str = "\033[33mACCEPT \033[0m";
        break;
    case TCP_EVENT_CLOSE:
        type_str = "\033[31mCLOSE  \033[0m";
        break;
    default:
        type_str = "UNKNOWN";
    }

    printf("%-8s %s pid=%-6d %-6s %s:%-5d → %s:%-5d\n",
           ts, type_str, e->pid, e->comm,
           src, e->sport, dst, e->dport);

    return 0;
}

int main(void)
{
    struct tcp_connect_bpf *skel;
    struct ring_buffer *rb;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = tcp_connect_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] 无法加载 BPF 程序\n");
        return 1;
    }

    err = tcp_connect_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] 无法挂载 BPF 程序\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) { err = -1; goto cleanup; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] TCP 连接监控启动（IPv4 + IPv6）\n");
    printf("[+] 按 Ctrl+C 退出\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

    ring_buffer__free(rb);
cleanup:
    tcp_connect_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

// ============================================================
// 05 - 函数耗时统计：用户空间程序
// 功能：读取 BPF 直方图并以 ASCII 图形展示耗时分布
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "func_latency.skel.h"
#include "func_latency.h"

static volatile int exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

// 将纳秒转换为人类可读的单位
static const char *ns_to_str(__u64 ns, char *buf, size_t len)
{
    if (ns < 1000)
        snprintf(buf, len, "%lluns", ns);
    else if (ns < 1000000)
        snprintf(buf, len, "%.2fus", ns / 1000.0);
    else if (ns < 1000000000)
        snprintf(buf, len, "%.2fms", ns / 1000000.0);
    else
        snprintf(buf, len, "%.2fs", ns / 1000000000.0);
    return buf;
}

// 打印 log2 直方图（ASCII 图形）
static void print_histogram(int hist_fd, __u64 total)
{
    int num_cpus = libbpf_num_possible_cpus();
    __u64 *values = calloc(num_cpus, sizeof(__u64));
    if (!values) return;

    // 先收集所有桶的数据
    __u64 counts[MAX_SLOTS] = {0};
    __u64 max_count = 0;

    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        if (bpf_map_lookup_elem(hist_fd, &i, values) == 0) {
            for (int cpu = 0; cpu < num_cpus; cpu++)
                counts[i] += values[cpu];
        }
        if (counts[i] > max_count) max_count = counts[i];
    }

    printf("\nvfs_read() 耗时分布（共 %llu 次调用）\n\n", total);
    printf("%-12s %-12s %-12s %s\n", "耗时范围", "次数", "占比", "分布图");
    printf("%-12s %-12s %-12s %s\n",
           "------------", "------------", "------------",
           "------------------------------------");

    char lo_str[32], hi_str[32];
    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        if (counts[i] == 0 && i > 0 && counts[i-1] == 0) continue;

        __u64 lo = (i == 0) ? 0 : (1ULL << (i - 1));
        __u64 hi = (1ULL << i) - 1;

        ns_to_str(lo, lo_str, sizeof(lo_str));
        ns_to_str(hi, hi_str, sizeof(hi_str));

        double pct = total ? (counts[i] * 100.0 / total) : 0;
        int bar_len = max_count ? (int)(counts[i] * 40 / max_count) : 0;

        printf("[%5s, %5s) %-12llu %6.2f%%   |",
               lo_str, hi_str, counts[i], pct);
        for (int j = 0; j < bar_len; j++) putchar('#');
        putchar('\n');
    }

    free(values);
}

// 处理慢调用事件
static int handle_slow_event(void *ctx, void *data, size_t data_sz)
{
    const struct latency_event *e = data;
    char dur_str[32];
    ns_to_str(e->duration_ns, dur_str, sizeof(dur_str));
    printf("  [慢调用] pid=%-6d comm=%-16s duration=%s\n",
           e->pid, e->comm, dur_str);
    return 0;
}

int main(void)
{
    struct func_latency_bpf *skel;
    struct ring_buffer *rb;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = func_latency_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] 无法加载 BPF 程序\n");
        return 1;
    }

    err = func_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] 无法挂载 BPF 程序\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_slow_event, NULL, NULL);
    if (!rb) { err = -1; goto cleanup; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] 开始统计 vfs_read() 耗时...\n");
    printf("[+] 每 3 秒输出一次，按 Ctrl+C 退出\n\n");

    int hist_fd = bpf_map__fd(skel->maps.histogram);
    int total_fd = bpf_map__fd(skel->maps.total_calls);
    __u32 zero = 0;

    while (!exiting) {
        // 轮询慢调用事件（非阻塞）
        ring_buffer__poll(rb, 100);

        static int tick = 0;
        if (++tick >= 30) { // 约 3 秒（30 * 100ms）
            tick = 0;
            __u64 total = 0;
            bpf_map_lookup_elem(total_fd, &zero, &total);
            print_histogram(hist_fd, total);
        }
    }

    // 最终输出
    printf("\n=== 最终统计 ===\n");
    __u64 total = 0;
    bpf_map_lookup_elem(total_fd, &zero, &total);
    print_histogram(hist_fd, total);

    ring_buffer__free(rb);
cleanup:
    func_latency_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

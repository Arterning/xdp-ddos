// ============================================================
// 07 - XDP DDoS 防护：用户空间控制程序
//
// 功能:
//   - 挂载 XDP 防护程序到指定网卡
//   - 实时显示防护统计（通过/丢弃包数）
//   - 监听黑名单事件（有 IP 被自动拉黑时告警）
//   - 支持手动添加/查看黑名单
//   - 支持动态修改限速阈值
//
// 用法:
//   sudo ./xdp_ddos -i eth0              # 默认配置
//   sudo ./xdp_ddos -i eth0 --skb-mode  # WSL2/虚拟机
//   sudo ./xdp_ddos -i eth0 --pps 500   # 设置每 IP 500pps 限速
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_ddos.skel.h"
#include "xdp_ddos.h"

static volatile int exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

// 处理黑名单事件（有 IP 被自动拉黑）
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct blacklist_event *e = data;
    char ip_str[INET_ADDRSTRLEN];
    char ts[32];
    time_t t; struct tm *tm;

    time(&t); tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &e->src_ip, ip_str, sizeof(ip_str));

    const char *reason = (e->reason == BL_REASON_SYN_FLOOD) ?
                         "SYN Flood" : "Rate Limit";

    printf("\033[31m[%s] 🔴 IP 已拉黑: %-16s 原因: %-12s 已丢弃: %llu 包\033[0m\n",
           ts, ip_str, reason, e->drop_count);
    fflush(stdout);
    return 0;
}

// 读取 PERCPU_ARRAY 并求和
static __u64 read_stats_sum(int fd, __u32 idx)
{
    int num_cpus = libbpf_num_possible_cpus();
    __u64 *values = calloc(num_cpus, sizeof(__u64));
    __u64 total = 0;
    if (!values) return 0;

    if (bpf_map_lookup_elem(fd, &idx, values) == 0)
        for (int i = 0; i < num_cpus; i++)
            total += values[i];

    free(values);
    return total;
}

// 打印实时统计
static void print_stats(int stats_fd, int bl_fd, const char *iface)
{
    __u64 pass     = read_stats_sum(stats_fd, STATS_PASS);
    __u64 drop     = read_stats_sum(stats_fd, STATS_DROP);
    __u64 bl_drop  = read_stats_sum(stats_fd, STATS_BLACKLIST);
    __u64 total    = pass + drop + bl_drop;
    double drop_pct = total ? (drop + bl_drop) * 100.0 / total : 0;

    // 统计黑名单中的 IP 数量
    __u32 bl_count = 0;
    __u32 key = 0, next_key;
    while (bpf_map_get_next_key(bl_fd, &key, &next_key) == 0) {
        bl_count++;
        key = next_key;
    }

    printf("\033[2J\033[H"); // 清屏
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║    XDP DDoS 防护统计   接口: %-8s           ║\n", iface);
    printf("╠══════════════════════╦═══════════════════════════╣\n");
    printf("║ 通过                 ║ %-25llu ║\n", pass);
    printf("║ 限速丢弃             ║ %-25llu ║\n", drop);
    printf("║ 黑名单丢弃           ║ %-25llu ║\n", bl_drop);
    printf("║ 总计                 ║ %-25llu ║\n", total);
    printf("║ 丢弃率               ║ %-24.2f%% ║\n", drop_pct);
    printf("╠══════════════════════╩═══════════════════════════╣\n");
    printf("║ 黑名单 IP 数量: %-5u                            ║\n", bl_count);
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("按 Ctrl+C 退出\n");
}

// 初始化配置到 config map
static void init_config(int cfg_fd, __u32 max_pps, __u32 burst,
                         __u32 syn_thresh, __u32 bl_thresh, __u32 bl_dur)
{
    __u32 zero = 0;
    struct ddos_config cfg = {
        .max_pps              = max_pps,
        .burst_size           = burst,
        .syn_threshold        = syn_thresh,
        .blacklist_threshold  = bl_thresh,
        .blacklist_duration_s = bl_dur,
    };
    bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "用法: %s -i <接口> [选项]\n"
            "  -i, --iface <name>   网络接口（必填）\n"
            "  -p, --pps <n>        每 IP 限速（包/秒，默认 %d）\n"
            "  -b, --burst <n>      令牌桶突发容量（默认 %d）\n"
            "  -s, --skb-mode       使用 SKB 模式（WSL2/虚拟机）\n"
            "  -B, --block <ip>     手动封锁 IP\n"
            "  -h, --help           显示帮助\n",
            prog, DEFAULT_MAX_PPS, DEFAULT_BURST_SIZE);
}

int main(int argc, char **argv)
{
    struct xdp_ddos_bpf *skel;
    char iface[IF_NAMESIZE] = "";
    char block_ip[64] = "";
    int  skb_mode = 0;
    __u32 max_pps = DEFAULT_MAX_PPS;
    __u32 burst   = DEFAULT_BURST_SIZE;
    int err, ifindex;

    static struct option opts[] = {
        {"iface",    required_argument, 0, 'i'},
        {"pps",      required_argument, 0, 'p'},
        {"burst",    required_argument, 0, 'b'},
        {"skb-mode", no_argument,       0, 's'},
        {"block",    required_argument, 0, 'B'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "i:p:b:sB:h", opts, NULL)) != -1) {
        switch (c) {
        case 'i': strncpy(iface, optarg, sizeof(iface) - 1);     break;
        case 'p': max_pps = atoi(optarg);                         break;
        case 'b': burst   = atoi(optarg);                         break;
        case 's': skb_mode = 1;                                   break;
        case 'B': strncpy(block_ip, optarg, sizeof(block_ip)-1); break;
        default:  usage(argv[0]); return 1;
        }
    }

    if (!iface[0]) {
        fprintf(stderr, "[-] 请指定网络接口（-i <接口名>）\n");
        usage(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "[-] 接口 %s 不存在\n", iface);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    skel = xdp_ddos_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] 无法加载 BPF 程序\n");
        return 1;
    }

    // 写入配置
    init_config(bpf_map__fd(skel->maps.cfg_map),
                max_pps, burst,
                DEFAULT_SYN_THRESHOLD,
                DEFAULT_BLACKLIST_THRESH,
                DEFAULT_BLACKLIST_DUR_S);

    // 挂载 XDP 程序
    __u32 xdp_flags = skb_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    err = bpf_xdp_attach(ifindex,
                          bpf_program__fd(skel->progs.xdp_ddos_protect),
                          xdp_flags, NULL);
    if (err) {
        fprintf(stderr, "[-] XDP 挂载失败: %d\n", err);
        if (!skb_mode)
            fprintf(stderr, "    提示: WSL2/虚拟机请添加 --skb-mode\n");
        goto cleanup;
    }

    printf("[+] XDP DDoS 防护已启动（接口: %s，模式: %s）\n",
           iface, skb_mode ? "SKB" : "Native");
    printf("[+] 配置: 限速=%d pps，突发=%d 包，SYN阈值=%d/s\n",
           max_pps, burst, DEFAULT_SYN_THRESHOLD);

    // 手动封锁 IP
    if (block_ip[0]) {
        __u32 ip; __u8 reason = BL_REASON_RATE_LIMIT;
        if (inet_pton(AF_INET, block_ip, &ip) == 1) {
            struct ddos_blacklist_entry entry = {
                .added_ns = 0, .drop_count = 0, .reason = reason
            };
            bpf_map_update_elem(bpf_map__fd(skel->maps.blacklist),
                                &ip, &entry, BPF_ANY);
            printf("[+] 手动封锁 IP: %s\n", block_ip);
        }
    }

    // 设置事件监听（黑名单通知）
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { err = -1; goto detach; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int stats_fd = bpf_map__fd(skel->maps.stats);
    int bl_fd    = bpf_map__fd(skel->maps.blacklist);

    while (!exiting) {
        // 非阻塞轮询事件（有黑名单告警时立即打印）
        ring_buffer__poll(rb, 100);

        // 每秒刷新统计
        static int tick = 0;
        if (++tick >= 10) {
            tick = 0;
            print_stats(stats_fd, bl_fd, iface);
        }
    }

    ring_buffer__free(rb);

detach:
    printf("\n[*] 正在卸载 XDP 程序...\n");
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    printf("[+] 完成\n");

cleanup:
    xdp_ddos_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

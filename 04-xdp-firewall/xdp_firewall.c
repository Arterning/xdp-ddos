// ============================================================
// 04 - XDP 防火墙：用户空间程序
//
// 功能:
//   - 将 XDP 程序挂载到指定网络接口
//   - 实时显示各协议流量统计
//   - 支持命令行动态添加/删除 IP 黑名单
//
// 用法:
//   sudo ./xdp_firewall -i eth0            # 挂载到 eth0
//   sudo ./xdp_firewall -i eth0 --skb-mode # WSL2/虚拟机使用 SKB 模式
//   sudo ./xdp_firewall -i eth0 -b 1.2.3.4 # 封锁 IP
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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_firewall.skel.h"
#include "xdp_firewall.h"

static volatile int exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static const char *proto_names[PROTO_MAX] = {
    [PROTO_TCP]   = "TCP",
    [PROTO_UDP]   = "UDP",
    [PROTO_ICMP]  = "ICMP",
    [PROTO_OTHER] = "OTHER",
};

// 读取 PERCPU_ARRAY 并求各 CPU 之和
static void print_stats(int stats_fd)
{
    int num_cpus = libbpf_num_possible_cpus();
    struct proto_stats *values = calloc(num_cpus, sizeof(*values));
    if (!values) return;

    printf("\033[2J\033[H"); // 清屏
    printf("╔══════════════════════════════════════════╗\n");
    printf("║        XDP 流量统计（实时）              ║\n");
    printf("╠══════╦══════════════╦═════════════════════╣\n");
    printf("║ 协议 ║     包数     ║        字节数       ║\n");
    printf("╠══════╬══════════════╬═════════════════════╣\n");

    for (__u32 i = 0; i < PROTO_MAX; i++) {
        struct proto_stats total = {0};

        // 查询 PERCPU_ARRAY：每个 CPU 的值存在独立槽位
        if (bpf_map_lookup_elem(stats_fd, &i, values) == 0) {
            for (int cpu = 0; cpu < num_cpus; cpu++) {
                total.packets += values[cpu].packets;
                total.bytes   += values[cpu].bytes;
            }
        }

        printf("║ %-4s ║ %12llu ║ %19llu ║\n",
               proto_names[i], total.packets, total.bytes);
    }

    printf("╚══════╩══════════════╩═════════════════════╝\n");
    printf("\n按 Ctrl+C 退出 | 实时刷新间隔 1 秒\n");
    free(values);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "用法: %s -i <接口> [选项]\n"
            "  -i, --iface <name>  网络接口名（必填）\n"
            "  -b, --block <ip>    封锁 IPv4 地址\n"
            "  -u, --unblock <ip>  解封 IPv4 地址\n"
            "  -s, --skb-mode      使用 SKB 模式（WSL2/虚拟机）\n"
            "  -h, --help          显示帮助\n"
            "例:\n"
            "  sudo %s -i eth0\n"
            "  sudo %s -i eth0 --skb-mode\n"
            "  sudo %s -i eth0 -b 192.168.1.100\n",
            prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct xdp_firewall_bpf *skel;
    char iface[IF_NAMESIZE] = "";
    char block_ip[64] = "";
    int skb_mode = 0;
    int err, ifindex;
    __u32 xdp_flags;

    static struct option opts[] = {
        {"iface",   required_argument, 0, 'i'},
        {"block",   required_argument, 0, 'b'},
        {"skb-mode",no_argument,       0, 's'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "i:b:sh", opts, NULL)) != -1) {
        switch (c) {
        case 'i': strncpy(iface, optarg, sizeof(iface) - 1); break;
        case 'b': strncpy(block_ip, optarg, sizeof(block_ip) - 1); break;
        case 's': skb_mode = 1; break;
        default: usage(argv[0]); return 1;
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

    skel = xdp_firewall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] 无法加载 BPF 程序\n");
        return 1;
    }

    // XDP 挂载模式：
    //   XDP_FLAGS_DRV_MODE  = Native XDP（需要网卡驱动支持，性能最佳）
    //   XDP_FLAGS_SKB_MODE  = Generic XDP（任何网卡都支持，性能稍差）
    //   WSL2 和多数虚拟机只支持 SKB 模式
    xdp_flags = skb_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    err = bpf_xdp_attach(ifindex,
                          bpf_program__fd(skel->progs.xdp_firewall_prog),
                          xdp_flags, NULL);
    if (err) {
        fprintf(stderr, "[-] XDP 挂载失败（接口: %s）: %d\n", iface, err);
        if (!skb_mode)
            fprintf(stderr, "    提示: WSL2/虚拟机请添加 --skb-mode 参数\n");
        goto cleanup;
    }

    printf("[+] XDP 防火墙已挂载到 %s（%s 模式）\n",
           iface, skb_mode ? "SKB" : "Native");

    // 如果指定了要封锁的 IP
    if (block_ip[0]) {
        __u32 ip;
        __u8  val = 1;
        if (inet_pton(AF_INET, block_ip, &ip) != 1) {
            fprintf(stderr, "[-] 无效的 IP 地址: %s\n", block_ip);
        } else {
            int bl_fd = bpf_map__fd(skel->maps.blocklist);
            bpf_map_update_elem(bl_fd, &ip, &val, BPF_ANY);
            printf("[+] 已封锁 IP: %s\n", block_ip);
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int stats_fd = bpf_map__fd(skel->maps.stats);
    while (!exiting) {
        print_stats(stats_fd);
        sleep(1);
    }

    printf("\n[*] 正在卸载 XDP 程序...\n");
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    printf("[+] 完成\n");

cleanup:
    xdp_firewall_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

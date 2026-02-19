#ifndef __XDP_FIREWALL_H
#define __XDP_FIREWALL_H

// 协议统计索引
#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_ICMP  2
#define PROTO_OTHER 3
#define PROTO_MAX   4

// 每个协议的流量统计
struct proto_stats {
    __u64 packets;   // 包数量
    __u64 bytes;     // 字节数
};

// 规则动作
#define ACTION_PASS  0
#define ACTION_DROP  1

// 防火墙规则（按 IPv4 源地址匹配）
struct fw_rule {
    __u32 src_ip;    // 源 IP（0 = 通配）
    __u8  action;    // ACTION_PASS 或 ACTION_DROP
    __u8  pad[3];
};

#endif /* __XDP_FIREWALL_H */

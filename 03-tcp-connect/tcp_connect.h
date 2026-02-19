#ifndef __TCP_CONNECT_H
#define __TCP_CONNECT_H

#include <linux/in6.h>

#define TASK_COMM_LEN 16

// 地址族
#define AF_INET  2
#define AF_INET6 10

// TCP 事件类型
enum tcp_event_type {
    TCP_EVENT_CONNECT  = 1,  // 主动发起连接（connect 成功）
    TCP_EVENT_ACCEPT   = 2,  // 被动接受连接（accept）
    TCP_EVENT_CLOSE    = 3,  // 连接关闭
};

// TCP 连接事件
struct tcp_event {
    enum tcp_event_type type;
    __u32 pid;
    __u32 ppid;
    __u16 af;               // AF_INET 或 AF_INET6
    __u16 sport;            // 源端口（主机字节序）
    __u16 dport;            // 目标端口（主机字节序）

    // 源/目标 IP（IPv4 存在低 32 位，IPv6 存 128 位）
    union {
        __u32 saddr;
        __u8  saddr6[16];
    };
    union {
        __u32 daddr;
        __u8  daddr6[16];
    };

    char comm[TASK_COMM_LEN];
};

#endif /* __TCP_CONNECT_H */

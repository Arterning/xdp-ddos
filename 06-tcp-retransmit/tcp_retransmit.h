#ifndef __TCP_RETRANSMIT_H
#define __TCP_RETRANSMIT_H

#define TASK_COMM_LEN 16
#define AF_INET       2
#define AF_INET6      10

// 重传事件类型
enum retransmit_type {
    RETRANSMIT_SKB   = 1,  // 数据段重传
    RETRANSMIT_SYNACK = 2, // SYN-ACK 重传
};

// TCP 重传事件
struct retransmit_event {
    enum retransmit_type type;
    __u32 pid;
    __u16 af;        // AF_INET 或 AF_INET6
    __u16 sport;     // 源端口
    __u16 dport;     // 目标端口
    __u8  state;     // TCP 状态
    __u8  pad;

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

#endif /* __TCP_RETRANSMIT_H */

#ifndef __HELLO_H
#define __HELLO_H

// 内核态与用户态共享的数据结构
// 通过 Ring Buffer 传递，必须保持两侧定义一致

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 128

// execve 事件：每次有进程调用 execve() 启动新程序时产生
struct event {
    __u32 pid;                         // 新进程 PID（TGID）
    __u32 ppid;                        // 父进程 PID
    char  comm[TASK_COMM_LEN];         // 调用 execve 的进程名（父进程）
    char  filename[MAX_FILENAME_LEN];  // 被执行的可执行文件路径
};

#endif /* __HELLO_H */

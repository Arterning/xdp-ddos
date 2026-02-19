#ifndef __PROCESS_MONITOR_H
#define __PROCESS_MONITOR_H

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 128

// 事件类型
enum event_type {
    EVENT_EXEC = 1,  // execve 执行新程序
    EVENT_FORK = 2,  // fork/clone 创建子进程
    EVENT_EXIT = 3,  // 进程退出
};

// 进程事件结构体（通过 Ring Buffer 传递）
struct proc_event {
    enum event_type type;             // 事件类型
    __u32 pid;                        // 当前进程 PID
    __u32 ppid;                       // 父进程 PID
    __u32 child_pid;                  // 子进程 PID（仅 FORK 事件有效）
    int   exit_code;                  // 退出码（仅 EXIT 事件有效）
    __u64 duration_ns;                // 进程运行时长（仅 EXIT 事件有效）
    char  comm[TASK_COMM_LEN];        // 进程名
    char  filename[MAX_FILENAME_LEN]; // 执行文件路径（仅 EXEC 事件有效）
};

#endif /* __PROCESS_MONITOR_H */

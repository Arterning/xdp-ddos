# 01 - Hello World eBPF

## 目标

验证环境，理解 eBPF 程序的完整生命周期。

**功能**：监听 `execve()` 系统调用，每当有程序被启动时打印进程信息。

## 两种实现对比

### BPFTrace 版（快速体验）

```bash
sudo bpftrace hello.bt
```

**特点**：无需编译，即写即跑，适合快速验证思路。

```
TIME     PID    PPID   COMM                 FILENAME
08:23:41 12345  1234   bash                 /bin/ls
```

### libbpf C 版（完整实现）

```bash
make && sudo ./hello
```

**特点**：生产级别，可打包部署，CO-RE 跨内核版本兼容。

## 编译流程

```
hello.bpf.c
    │ ① clang -target bpf -O2 -g
    ▼
hello.bpf.o          ← BPF ELF 字节码（不是 x86，是 BPF ISA）
    │ ② bpftool gen skeleton
    ▼
hello.skel.h         ← 自动生成的"骨架"（封装了 load/attach/destroy）
    │ ③ clang + hello.c
    ▼
hello                ← 最终可执行文件（用户空间程序）
```

## 核心概念

| 概念 | 说明 |
|------|------|
| **Tracepoint** | `tp/syscalls/sys_enter_execve`：execve 入口，稳定 ABI |
| **Ring Buffer** | `BPF_MAP_TYPE_RINGBUF`：内核→用户空间的高效事件通道 |
| **Skeleton** | `hello.skel.h`：bpftool 自动生成，包含 open/load/attach 函数 |
| **CO-RE** | 编译时嵌入 BTF 重定位信息，运行时适配内核版本 |
| **BPF_CORE_READ** | 使用 BTF 安全读取 `task_struct` 等内核结构体 |

## 文件结构

```
01-hello-world/
├── hello.bt       # BPFTrace 脚本（快速原型）
├── hello.h        # 内核/用户共享的数据结构
├── hello.bpf.c    # BPF 内核态程序（运行在内核中）
├── hello.c        # 用户空间程序（加载 + 接收事件）
└── Makefile       # 编译系统
```

## 调试技巧

```bash
# 查看 BPF 字节码反汇编
llvm-objdump -S hello.bpf.o

# 查看加载到内核的 BPF 程序
sudo bpftool prog list

# 查看 BPF map
sudo bpftool map list

# bpf_printk 的输出位置
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

# eBPF 实战教学项目

本项目包含从入门到进阶的 eBPF 示例程序，面向教学用途，代码注释详尽。

## 项目列表

| 目录 | 说明 | 难度 |
|------|------|------|
| [01-hello-world](./01-hello-world/) | 环境验证 + 第一个 eBPF 程序 | ⭐ 入门 |
| [02-process-monitor](./02-process-monitor/) | 进程 exec/fork 监控 | ⭐⭐ 基础 |
| [03-tcp-connect](./03-tcp-connect/) | TCP 连接监控（IPv4/IPv6） | ⭐⭐⭐ 中级 |
| [04-xdp-firewall](./04-xdp-firewall/) | XDP 流量统计 + 简易防火墙 | ⭐⭐⭐ 中级 |
| [05-func-latency](./05-func-latency/) | 内核函数耗时统计（直方图） | ⭐⭐⭐ 中级 |
| [06-tcp-retransmit](./06-tcp-retransmit/) | TCP 重传监控 | ⭐⭐⭐ 中级 |
| [07-xdp-ddos](./07-xdp-ddos/) | XDP 毫秒级 DDoS 防护 | ⭐⭐⭐⭐ 进阶 |

## 环境要求

- Linux 内核 **≥ 5.10**（推荐 5.15+ LTS）
- Windows 用户请使用 **WSL2**（Ubuntu 22.04 推荐）
- 内核需要开启 **BTF**（大多数发行版默认开启）

## 环境搭建

### WSL2 用户（Windows）

```bash
# 1. 安装 WSL2 + Ubuntu 22.04
wsl --install -d Ubuntu-22.04

# 2. 进入 WSL2 后运行安装脚本
chmod +x setup.sh && sudo ./setup.sh

# 3. 验证内核 BTF 支持
ls /sys/kernel/btf/vmlinux  # 存在即支持
```

### Linux 原生

```bash
sudo ./setup.sh
```

## 编译与运行

```bash
# 编译单个项目
cd 01-hello-world && make

# 编译所有项目
make all

# 运行（需要 root 权限）
sudo ./hello
```

## 技术栈

- **libbpf**：官方推荐的 BPF 用户空间库
- **CO-RE**（Compile Once – Run Everywhere）：一次编译，跨内核版本运行
- **BTF**（BPF Type Format）：CO-RE 的基础
- **bpftool**：BPF 工具集（骨架生成、map 操作等）
- **Ring Buffer**：现代 BPF 事件传递机制（比 perf buffer 更高效）

## 学习路径

```
01 入门  →  02 进程  →  03 TCP  →  04 XDP 基础
                                        ↓
                              05 延迟分析  ←  06 TCP重传  ←  07 DDoS防护
```

## 常见问题

**Q: 编译报错找不到 vmlinux.h？**
A: 运行 `make vmlinux.h` 或直接 `make`，Makefile 会自动生成。

**Q: 挂载 XDP 失败？**
A: WSL2 默认网络接口不支持 native XDP，使用 SKB 模式：`sudo ./xdp_firewall -i eth0 --skb-mode`

**Q: bpf_printk 的输出在哪？**
A: `sudo cat /sys/kernel/debug/tracing/trace_pipe`

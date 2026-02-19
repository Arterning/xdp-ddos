# 07 - XDP 毫秒级 DDoS 防护

## 为什么 XDP 能实现毫秒级响应？

```
传统 iptables 防护路径：
  网卡 → 硬件中断 → 内存分配(skb) → 网络栈 → netfilter/iptables → DROP
  延迟：数十微秒 ~ 毫秒级，受内核网络栈影响

XDP 防护路径：
  网卡 → XDP 程序（驱动层直接执行）→ XDP_DROP
  延迟：< 1 微秒，完全绕过内核网络栈
```

XDP 在 skb（socket buffer）**分配之前**运行，这意味着：
- 不涉及内存分配
- 不涉及协议栈处理
- 单核可处理 **10+ Mpps**（一千万包/秒）

## 防护机制

```
收到数据包
    │
    ├─① 黑名单检查（O(1) hash）──── 命中 → XDP_DROP（最快）
    │
    ├─② SYN Flood 检测（滑动窗口）─ 超阈值 → 自动拉黑 + XDP_DROP
    │
    ├─③ 令牌桶限速（per-IP）─────── 超速 → XDP_DROP + 计数
    │                                命中 N 次 → 自动拉黑
    │
    └─ XDP_PASS → 进入正常网络栈
```

### 令牌桶算法（Token Bucket）

```
令牌桶容量 = burst_size（默认 200）
令牌补充率 = max_pps/秒（默认 1000 包/秒）

每收到一个包：
  1. 根据距上次检查的时间，补充对应数量的令牌
  2. 如有令牌 → 消耗 1 个 → XDP_PASS
  3. 无令牌   → rate_limit_hits++ → XDP_DROP
  4. hits >= blacklist_threshold → 自动拉黑
```

## 编译与运行

```bash
make

# 普通 Linux
sudo ./xdp_ddos -i eth0

# WSL2 / 虚拟机（不支持 Native XDP，使用 SKB 模式）
sudo ./xdp_ddos -i eth0 --skb-mode

# 自定义限速（每 IP 每秒 500 包，突发允许 100 包）
sudo ./xdp_ddos -i eth0 --pps 500 --burst 100

# 手动封锁 IP
sudo ./xdp_ddos -i eth0 -B 192.168.1.100
```

## 预期输出

```
[+] XDP DDoS 防护已启动（接口: eth0，模式: Native）
[+] 配置: 限速=1000 pps，突发=200 包，SYN阈值=500/s

╔══════════════════════════════════════════════════╗
║    XDP DDoS 防护统计   接口: eth0                ║
╠══════════════════════╦═══════════════════════════╣
║ 通过                 ║ 124832                    ║
║ 限速丢弃             ║ 8921                      ║
║ 黑名单丢弃           ║ 45123                     ║
║ 丢弃率               ║ 30.44%                    ║
╚══════════════════════╩═══════════════════════════╝

[10:23:41] 🔴 IP 已拉黑: 192.168.1.50   原因: SYN Flood   已丢弃: 12300 包
```

## 文件结构

```
07-xdp-ddos/
├── xdp_ddos.h       # 共享数据结构（config, token_bucket, blacklist_entry）
├── xdp_ddos.bpf.c  # XDP BPF 程序（内核态，每包执行）
├── xdp_ddos.c      # 用户空间控制程序
└── Makefile
```

## 关键 BPF 技术点

| 技术 | 说明 |
|------|------|
| `BPF_MAP_TYPE_LRU_HASH` | 自动淘汰最旧条目，避免内存耗尽 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | 无锁 per-CPU 统计，最高性能 |
| `bpf_ktime_get_ns()` | 纳秒精度单调时钟，用于令牌桶计时 |
| `bpf_ringbuf_reserve/submit` | 异步通知用户空间（黑名单告警） |
| `__sync_fetch_and_add` | BPF 原子操作 |

## 注意事项

- WSL2 内核不支持 Native XDP，必须使用 `--skb-mode`
- SKB 模式性能低于 Native 模式，但功能完全相同
- 生产环境应在专用服务器或支持 Native XDP 的网卡（Intel X710 等）上部署

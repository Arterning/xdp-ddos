#!/bin/bash
# eBPF 开发环境安装脚本
# 支持 Ubuntu 20.04 / 22.04 / Debian 11+
# 用法: sudo ./setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then
    error "请以 root 权限运行: sudo ./setup.sh"
fi

info "检查系统环境..."
KERNEL_VER=$(uname -r)
info "内核版本: $KERNEL_VER"

# 检查 BTF 支持
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    warn "未找到 /sys/kernel/btf/vmlinux，CO-RE 可能不可用"
    warn "请确保内核编译时开启了 CONFIG_DEBUG_INFO_BTF=y"
else
    info "BTF 支持: OK"
fi

info "更新软件包列表..."
apt-get update -q

info "安装编译工具链..."
apt-get install -y \
    clang \
    llvm \
    gcc \
    make \
    pkg-config \
    libelf-dev \
    zlib1g-dev \
    linux-headers-$(uname -r) \
    linux-tools-common \
    linux-tools-$(uname -r) 2>/dev/null || true

info "安装 libbpf 开发库..."
apt-get install -y libbpf-dev 2>/dev/null || {
    warn "libbpf-dev 未找到，尝试从源码编译..."
    apt-get install -y git libelf-dev zlib1g-dev
    git clone --depth 1 https://github.com/libbpf/libbpf.git /tmp/libbpf
    make -C /tmp/libbpf/src install
    ldconfig
}

info "安装 bpftool..."
# Ubuntu 22.04+ 可以直接安装
apt-get install -y linux-tools-$(uname -r) 2>/dev/null || \
apt-get install -y bpftool 2>/dev/null || {
    warn "bpftool 未找到，尝试编译安装..."
    # 从 linux-tools 或者源码
    apt-get install -y linux-tools-generic 2>/dev/null || true
}

# 确认 bpftool 可用
if ! command -v bpftool &>/dev/null; then
    # 尝试查找 bpftool 位置
    BPFTOOL_PATH=$(find /usr -name "bpftool" 2>/dev/null | head -1)
    if [ -n "$BPFTOOL_PATH" ]; then
        ln -sf "$BPFTOOL_PATH" /usr/local/bin/bpftool
        info "bpftool 链接到: $BPFTOOL_PATH"
    else
        warn "bpftool 未找到，请手动安装或从源码编译"
    fi
fi

info "安装调试工具..."
apt-get install -y \
    strace \
    tcpdump \
    iproute2 \
    iputils-ping \
    netcat-openbsd 2>/dev/null || true

info "验证安装..."
echo ""
echo "=========================================="
echo "  工具版本信息"
echo "=========================================="
clang --version | head -1 || warn "clang 未安装"
echo ""
llvm-strip --version 2>/dev/null | head -1 || warn "llvm-strip 未找到"
echo ""
bpftool version 2>/dev/null || warn "bpftool 未找到"
echo ""

info "挂载调试文件系统..."
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true

echo ""
echo "=========================================="
info "安装完成！"
echo "=========================================="
echo ""
echo "下一步:"
echo "  1. cd 01-hello-world"
echo "  2. make"
echo "  3. sudo ./hello"
echo ""
echo "查看 BPF 输出:"
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"

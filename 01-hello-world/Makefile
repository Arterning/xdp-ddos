# ============================================================
# 01-hello-world Makefile
# 编译流程：
#   hello.bpf.c  →(clang -target bpf)→  hello.bpf.o
#   hello.bpf.o  →(bpftool gen skeleton)→  hello.skel.h
#   hello.c + hello.skel.h  →(clang)→  hello
# ============================================================

CLANG   ?= clang
BPFTOOL ?= bpftool

# 自动检测目标架构（x86_64 → x86，aarch64 → arm64）
ARCH := $(shell uname -m | sed 's/x86_64/x86/' \
                          | sed 's/aarch64/arm64/' \
                          | sed 's/loongarch64/loongarch/')

# BPF 内核程序编译参数
BPF_CFLAGS := \
    -g -O2 \
    -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I/usr/include \
    -I/usr/include/$(shell uname -m)-linux-gnu \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types

# 用户空间程序编译参数
USER_CFLAGS := -g -O2 -Wall

# 链接库
LIBS := -lbpf -lelf -lz

APP := hello

.PHONY: all clean run run-bt

all: vmlinux.h $(APP)

# ① 生成 vmlinux.h
# CO-RE 需要 vmlinux.h 来获取内核类型定义
# 原理：bpftool 读取内核 BTF 信息并生成对应的 C 头文件
vmlinux.h:
	@echo "[*] 生成 vmlinux.h（从运行内核的 BTF 信息）..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "[-] 错误: /sys/kernel/btf/vmlinux 不存在"; \
		echo "    请确认内核开启了 CONFIG_DEBUG_INFO_BTF=y"; \
		exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "[+] vmlinux.h 生成完成"

# ② 编译 BPF 内核程序为 BPF 字节码
$(APP).bpf.o: $(APP).bpf.c vmlinux.h $(APP).h
	@echo "[*] 编译 BPF 程序..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[+] BPF 字节码生成: $@"

# ③ 生成骨架头文件
# bpftool gen skeleton 分析 BPF ELF，生成包含以下内容的头文件：
#   - BPF 对象的 open/load/attach/destroy 函数
#   - map 和 program 的访问接口
$(APP).skel.h: $(APP).bpf.o
	@echo "[*] 生成 BPF 骨架..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "[+] 骨架生成: $@"

# ④ 编译用户空间程序
$(APP): $(APP).c $(APP).skel.h $(APP).h
	@echo "[*] 编译用户空间程序..."
	$(CLANG) $(USER_CFLAGS) -o $@ $(APP).c $(LIBS)
	@echo "[+] 编译完成: $@"
	@echo ""
	@echo "运行方式:"
	@echo "  sudo ./$(APP)          # libbpf C 版本"
	@echo "  sudo bpftrace $(APP).bt  # BPFTrace 版本（无需编译）"

# 运行 libbpf C 版本
run: $(APP)
	sudo ./$(APP)

# 运行 BPFTrace 版本（无需编译，快速体验）
run-bt:
	@echo "[*] 运行 BPFTrace 版本..."
	sudo bpftrace $(APP).bt

clean:
	rm -f *.o *.skel.h vmlinux.h $(APP)
	@echo "[+] 清理完成"

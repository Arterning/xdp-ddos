CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
    -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu \
    -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types

USER_CFLAGS := -g -O2 -Wall
LIBS        := -lbpf -lelf -lz
APP         := xdp_ddos

.PHONY: all clean run
all: vmlinux.h $(APP)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(APP).bpf.o: $(APP).bpf.c vmlinux.h $(APP).h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(APP): $(APP).c $(APP).skel.h $(APP).h
	$(CLANG) $(USER_CFLAGS) -o $@ $(APP).c $(LIBS)

run: $(APP)
	@echo "用法: sudo ./$(APP) -i <接口>"
	@echo "WSL2:  sudo ./$(APP) -i eth0 --skb-mode"
	@echo "自定义: sudo ./$(APP) -i eth0 --pps 2000 --burst 500"

clean:
	rm -f *.o *.skel.h vmlinux.h $(APP)

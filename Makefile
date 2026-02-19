# 顶层 Makefile：编译所有 eBPF 示例

SUBDIRS := \
    01-hello-world \
    02-process-monitor \
    03-tcp-connect \
    04-xdp-firewall \
    05-func-latency \
    06-tcp-retransmit \
    07-xdp-ddos

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	@echo "==> 编译 $@ ..."
	$(MAKE) -C $@
	@echo ""

clean:
	@for dir in $(SUBDIRS); do \
		echo "==> 清理 $$dir ..."; \
		$(MAKE) -C $$dir clean; \
	done

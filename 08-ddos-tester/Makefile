CC     = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
APP    = flood

.PHONY: all clean

all: $(APP)
	@echo ""
	@echo "运行方式（需要 root）:"
	@echo "  sudo ./flood -d <目标IP> -s <源IP> -m syn   # SYN Flood"
	@echo "  sudo ./flood -d <目标IP> -s <源IP> -m udp   # UDP Flood"
	@echo "  sudo ./flood -d <目标IP> -m icmp             # ICMP Flood（随机源IP）"
	@echo "  sudo ./flood --help                          # 完整帮助"

$(APP): flood.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(APP)

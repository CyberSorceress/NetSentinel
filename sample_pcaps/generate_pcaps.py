"""
NetSentinel - Sample PCAP Dataset Generator
Generates realistic normal baseline and attack-pattern PCAP files using Scapy for immediate testing and demonstration.
"""

import os
import time
from typing import Dict, List

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    Raw,
    TCP,
    UDP,
    Ether,
    wrpcap,
)


def generate_normal_traffic_pcap(filepath: str) -> str:
    """Generates benign network traffic: ARP, DNS, TCP handshakes, HTTP, ICMP."""
    packets = []
    base_time = time.time() - 300

    # 1. ARP exchange
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / \
              ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.100",
                  hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
    arp_req.time = base_time
    packets.append(arp_req)

    arp_rep = Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee") / \
              ARP(op=2, hwsrc="00:aa:bb:cc:dd:ee", psrc="192.168.1.1",
                  hwdst="00:11:22:33:44:55", pdst="192.168.1.100")
    arp_rep.time = base_time + 0.005
    packets.append(arp_rep)

    # 2. DNS Query & Response
    dns_query = Ether() / IP(src="192.168.1.100", dst="1.1.1.1") / \
                UDP(sport=54321, dport=53) / \
                DNS(id=1001, qr=0, qd=DNSQR(qname="aman9673.github.io", qtype="A"))
    dns_query.time = base_time + 0.05
    packets.append(dns_query)

    dns_resp = Ether() / IP(src="1.1.1.1", dst="192.168.1.100") / \
               UDP(sport=53, dport=54321) / \
               DNS(id=1001, qr=1, ancount=1,
                   qd=DNSQR(qname="aman9673.github.io", qtype="A"),
                   an=DNSRR(rrname="aman9673.github.io", rdata="185.199.108.153", ttl=300))
    dns_resp.time = base_time + 0.07
    packets.append(dns_resp)

    # 3. HTTP Three-Way Handshake & Request
    # Client SYN
    syn = Ether() / IP(src="192.168.1.100", dst="185.199.108.153") / \
          TCP(sport=49152, dport=80, flags="S", seq=1000)
    syn.time = base_time + 0.10
    packets.append(syn)

    # Server SYN-ACK
    syn_ack = Ether() / IP(src="185.199.108.153", dst="192.168.1.100") / \
              TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001)
    syn_ack.time = base_time + 0.12
    packets.append(syn_ack)

    # Client ACK (Handshake complete)
    ack = Ether() / IP(src="192.168.1.100", dst="185.199.108.153") / \
          TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)
    ack.time = base_time + 0.13
    packets.append(ack)

    # HTTP GET
    http_payload = b"GET / HTTP/1.1\r\nHost: aman9673.github.io\r\nUser-Agent: NetSentinel-Probe/1.0\r\nAccept: */*\r\n\r\n"
    http_req = Ether() / IP(src="192.168.1.100", dst="185.199.108.153") / \
               TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001) / \
               Raw(load=http_payload)
    http_req.time = base_time + 0.14
    packets.append(http_req)

    # HTTP 200 OK Response
    http_resp_payload = b"HTTP/1.1 200 OK\r\nServer: GitHub.com\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body>NetSentinel Test Page</body></html>"
    http_resp = Ether() / IP(src="185.199.108.153", dst="192.168.1.100") / \
                TCP(sport=80, dport=49152, flags="PA", seq=5001, ack=1001 + len(http_payload)) / \
                Raw(load=http_resp_payload)
    http_resp.time = base_time + 0.16
    packets.append(http_resp)

    # Teardown FIN-ACK
    fin = Ether() / IP(src="192.168.1.100", dst="185.199.108.153") / \
          TCP(sport=49152, dport=80, flags="FA", seq=1001 + len(http_payload), ack=5001 + len(http_resp_payload))
    fin.time = base_time + 0.20
    packets.append(fin)

    # 4. ICMP Echo Request & Reply
    for i in range(4):
        ping_req = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / \
                   ICMP(type=8, code=0, id=1234, seq=i + 1) / Raw(load=b"NetSentinel-Ping")
        ping_req.time = base_time + 1.0 + (i * 0.2)
        packets.append(ping_req)

        ping_rep = Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / \
                   ICMP(type=0, code=0, id=1234, seq=i + 1) / Raw(load=b"NetSentinel-Ping")
        ping_rep.time = base_time + 1.0 + (i * 0.2) + 0.015
        packets.append(ping_rep)

    wrpcap(filepath, packets)
    return filepath


def generate_port_scan_pcap(filepath: str) -> str:
    """Generates an Nmap horizontal SYN scan and stealth (NULL, XMAS) scan against multiple ports."""
    packets = []
    base_time = time.time() - 120
    target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080]

    for idx, port in enumerate(target_ports):
        # SYN probe
        syn_pkt = Ether() / IP(src="10.20.30.40", dst="192.168.1.10") / \
                  TCP(sport=40000 + idx, dport=port, flags="S", seq=1000 + idx)
        syn_pkt.time = base_time + (idx * 0.01)
        packets.append(syn_pkt)

        # Target replies with RST (port closed)
        rst_pkt = Ether() / IP(src="192.168.1.10", dst="10.20.30.40") / \
                  TCP(sport=port, dport=40000 + idx, flags="RA", seq=0, ack=1001 + idx)
        rst_pkt.time = base_time + (idx * 0.01) + 0.002
        packets.append(rst_pkt)

    # Add Stealth NULL Scan packet (no flags)
    null_pkt = Ether() / IP(src="10.20.30.40", dst="192.168.1.10") / \
               TCP(sport=55555, dport=80, flags=0, seq=500)
    null_pkt.time = base_time + 0.5
    packets.append(null_pkt)

    # Add Stealth XMAS Scan packet (FPU)
    xmas_pkt = Ether() / IP(src="10.20.30.40", dst="192.168.1.10") / \
               TCP(sport=55556, dport=80, flags="FPU", seq=501)
    xmas_pkt.time = base_time + 0.6
    packets.append(xmas_pkt)

    wrpcap(filepath, packets)
    return filepath


def generate_syn_flood_pcap(filepath: str) -> str:
    """Generates a high-rate TCP SYN flood Denial-of-Service attack with no ACK completions."""
    packets = []
    base_time = time.time() - 60

    for i in range(40):
        attacker_ip = f"172.16.5.{10 + (i % 5)}"
        syn_pkt = Ether() / IP(src=attacker_ip, dst="192.168.1.10") / \
                  TCP(sport=10000 + i, dport=80, flags="S", seq=50000 + i)
        syn_pkt.time = base_time + (i * 0.005)
        packets.append(syn_pkt)

    wrpcap(filepath, packets)
    return filepath


def generate_dns_tunneling_pcap(filepath: str) -> str:
    """Generates DNS data exfiltration queries with high-entropy long domain names."""
    packets = []
    base_time = time.time() - 90

    encoded_subdomains = [
        "c2VjcmV0LWNvbmZpZGVudGlhbC1kYXRhLXZhdWx0LTAxOTI4MzgxMg.tunnel.malicious-exfil.org",
        "ODQ3ZjhhOWIyYzFkM2U0ZjVhNmI3YzhkOWUweTF6MnEzcjR0NXV2.data.c2-command.net",
        "ZXhwbG9pdC1wYXlsb2FkLWJ1ZmZlci1vdmVyZmxvdy1zaGVsbGNvZGU.beacon.darkweb-ops.io",
    ]

    for i, domain in enumerate(encoded_subdomains):
        query = Ether() / IP(src="192.168.1.88", dst="8.8.8.8") / \
                UDP(sport=61000 + i, dport=53) / \
                DNS(id=3000 + i, qr=0, qd=DNSQR(qname=domain, qtype="TXT"))
        query.time = base_time + (i * 0.1)
        packets.append(query)

    wrpcap(filepath, packets)
    return filepath


def generate_cleartext_creds_pcap(filepath: str) -> str:
    """Generates cleartext credential exposure (HTTP Basic Auth & FTP USER/PASS)."""
    packets = []
    base_time = time.time() - 45

    # HTTP Basic Auth: admin:Password123 -> YWRtaW46UGFzc3dvcmQxMjM=
    http_auth_payload = (
        b"GET /admin/dashboard HTTP/1.1\r\n"
        b"Host: 192.168.1.50\r\n"
        b"Authorization: Basic YWRtaW46UGFzc3dvcmQxMjM=\r\n"
        b"User-Agent: Mozilla/5.0\r\n\r\n"
    )
    auth_pkt = Ether() / IP(src="192.168.1.25", dst="192.168.1.50") / \
               TCP(sport=51234, dport=80, flags="PA", seq=100, ack=100) / \
               Raw(load=http_auth_payload)
    auth_pkt.time = base_time
    packets.append(auth_pkt)

    # FTP cleartext USER and PASS commands
    ftp_user_pkt = Ether() / IP(src="192.168.1.25", dst="192.168.1.50") / \
                   TCP(sport=51235, dport=21, flags="PA", seq=200, ack=200) / \
                   Raw(load=b"USER backup_admin\r\n")
    ftp_user_pkt.time = base_time + 0.1
    packets.append(ftp_user_pkt)

    ftp_pass_pkt = Ether() / IP(src="192.168.1.25", dst="192.168.1.50") / \
                   TCP(sport=51235, dport=21, flags="PA", seq=220, ack=200) / \
                   Raw(load=b"PASS SuperSecret456!\r\n")
    ftp_pass_pkt.time = base_time + 0.2
    packets.append(ftp_pass_pkt)

    wrpcap(filepath, packets)
    return filepath


def generate_all_samples(output_dir: str) -> Dict[str, str]:
    """Generates all demonstration PCAP files in the target directory."""
    os.makedirs(output_dir, exist_ok=True)
    generated = {
        "normal_traffic": generate_normal_traffic_pcap(os.path.join(output_dir, "normal_web_traffic.pcap")),
        "port_scan": generate_port_scan_pcap(os.path.join(output_dir, "syn_port_scan.pcap")),
        "syn_flood": generate_syn_flood_pcap(os.path.join(output_dir, "syn_flood_dos.pcap")),
        "dns_tunneling": generate_dns_tunneling_pcap(os.path.join(output_dir, "dns_tunneling.pcap")),
        "cleartext_creds": generate_cleartext_creds_pcap(os.path.join(output_dir, "cleartext_credentials.pcap")),
    }
    return generated


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    files = generate_all_samples(current_dir)
    print("Generated sample PCAPs successfully:")
    for name, path in files.items():
        print(f"  - {name}: {path} ({os.path.getsize(path)} bytes)")

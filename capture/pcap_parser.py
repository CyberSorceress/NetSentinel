"""
NetSentinel - Packet Capture & Protocol Analysis Layer
Deep packet inspection for offline PCAP/PCAPNG files using Scapy with optional PyShark / TShark engine.
"""

import os
import shutil
import struct
import time
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple

# Scapy imports
from scapy.all import (
    ARP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
    Ether,
    PcapReader,
    rdpcap,
)

# Optional PyShark import
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False


def find_tshark_path() -> Optional[str]:
    """Attempts to locate the tshark executable on Windows or Linux."""
    system_tshark = shutil.which("tshark")
    if system_tshark:
        return system_tshark

    # Common Windows installation locations
    windows_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
    ]
    for p in windows_paths:
        if os.path.isfile(p):
            return p
    return None


class PacketParser:
    """High-performance Scapy-based deep packet parser with protocol dissection."""

    def __init__(self, pcap_path: str):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.pcap_path = pcap_path

    def parse_packet_metadata(self, packet: Any, frame_num: int) -> Dict[str, Any]:
        """Extracts comprehensive metadata, headers, flags, and application layers."""
        pkt_time = float(packet.time) if hasattr(packet, "time") else time.time()
        pkt_len = len(packet)
        layers = [layer.__name__ for layer in packet.layers()]

        meta: Dict[str, Any] = {
            "frame_num": frame_num,
            "timestamp": pkt_time,
            "length": pkt_len,
            "layers": layers,
            "src_mac": None,
            "dst_mac": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": "OTHER",
            "flags": "",
            "info": "",
            "payload_hex": "",
            "details": {},
            "pcap_source": os.path.basename(self.pcap_path)
        }

        # 1. Layer 2: Ethernet / Data Link
        if packet.haslayer(Ether):
            meta["src_mac"] = packet[Ether].src
            meta["dst_mac"] = packet[Ether].dst

        # 2. ARP Protocol
        if packet.haslayer(ARP):
            arp = packet[ARP]
            meta["protocol"] = "ARP"
            meta["src_ip"] = arp.psrc
            meta["dst_ip"] = arp.pdst
            op = "who-has" if arp.op == 1 else ("is-at" if arp.op == 2 else f"op={arp.op}")
            meta["info"] = f"ARP {op} {arp.pdst} tell {arp.psrc}"
            meta["details"]["arp_op"] = arp.op
            meta["details"]["arp_src_mac"] = arp.hwsrc
            meta["details"]["arp_dst_mac"] = arp.hwdst
            return meta

        # 3. Layer 3: IPv4 / IPv6
        if packet.haslayer(IP):
            ip = packet[IP]
            meta["src_ip"] = ip.src
            meta["dst_ip"] = ip.dst
            meta["details"]["ip_ttl"] = ip.ttl
            meta["details"]["ip_tos"] = ip.tos
            meta["details"]["ip_id"] = ip.id
            meta["details"]["ip_flags"] = str(ip.flags)
        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            meta["src_ip"] = ip6.src
            meta["dst_ip"] = ip6.dst
            meta["details"]["ipv6_hlim"] = ip6.hlim

        # 4. Layer 4: TCP / UDP / ICMP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            meta["protocol"] = "TCP"
            meta["src_port"] = tcp.sport
            meta["dst_port"] = tcp.dport
            flags = str(tcp.flags)
            meta["flags"] = flags
            meta["details"]["tcp_seq"] = tcp.seq
            meta["details"]["tcp_ack"] = tcp.ack
            meta["details"]["tcp_window"] = tcp.window
            meta["info"] = f"TCP {tcp.sport} -> {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"

            # Inspect Application protocols over TCP
            self._inspect_tcp_application_layers(packet, meta)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            meta["protocol"] = "UDP"
            meta["src_port"] = udp.sport
            meta["dst_port"] = udp.dport
            meta["info"] = f"UDP {udp.sport} -> {udp.dport} Len={udp.len}"

            # Inspect Application protocols over UDP (DNS, DHCP)
            self._inspect_udp_application_layers(packet, meta)

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            meta["protocol"] = "ICMP"
            type_names = {
                0: "Echo Reply",
                3: "Dest Unreachable",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded"
            }
            t_name = type_names.get(icmp.type, f"Type={icmp.type}")
            meta["info"] = f"ICMP {t_name} (code={icmp.code})"
            meta["details"]["icmp_type"] = icmp.type
            meta["details"]["icmp_code"] = icmp.code

        # Extract Raw Payload if available
        if packet.haslayer(Raw):
            raw_bytes = bytes(packet[Raw].load)
            meta["payload_hex"] = raw_bytes[:128].hex()
            meta["details"]["payload_len"] = len(raw_bytes)

        return meta

    def _inspect_tcp_application_layers(self, packet: Any, meta: Dict[str, Any]):
        """Dissects HTTP, TLS ClientHello SNI, SSH, FTP, etc."""
        tcp = packet[TCP]
        payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""

        # TLS SNI Extraction (port 443 or TLS record header \x16\x03\x01 / \x16\x03\x03)
        if (tcp.dport == 443 or tcp.sport == 443) and payload.startswith(b"\x16\x03"):
            sni = self._extract_tls_sni(payload)
            if sni:
                meta["protocol"] = "TLS"
                meta["info"] = f"TLS ClientHello SNI: {sni}"
                meta["details"]["tls_sni"] = sni
            else:
                meta["protocol"] = "TLS"
                meta["info"] = f"TLS Handshake {tcp.sport} -> {tcp.dport}"

        # HTTP Inspection
        elif tcp.dport in [80, 8080] or tcp.sport in [80, 8080] or payload.startswith((b"GET ", b"POST ", b"HTTP/", b"HEAD ", b"PUT ", b"DELETE ")):
            meta["protocol"] = "HTTP"
            try:
                text_payload = payload.decode("latin-1", errors="ignore")
                lines = text_payload.split("\r\n")
                first_line = lines[0] if lines else ""
                meta["info"] = f"HTTP {first_line[:80]}"
                meta["details"]["http_line"] = first_line

                for line in lines[1:10]:
                    if line.lower().startswith("host:"):
                        meta["details"]["http_host"] = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("authorization:"):
                        meta["details"]["http_auth"] = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("user-agent:"):
                        meta["details"]["http_user_agent"] = line.split(":", 1)[1].strip()
            except Exception:
                pass

        # FTP (port 21)
        elif tcp.dport == 21 or tcp.sport == 21:
            meta["protocol"] = "FTP"
            try:
                line = payload.decode("latin-1", errors="ignore").strip()
                meta["info"] = f"FTP {line[:60]}"
                if line.upper().startswith(("USER ", "PASS ")):
                    meta["details"]["ftp_cmd"] = line
            except Exception:
                pass

        # SSH (port 22)
        elif tcp.dport == 22 or tcp.sport == 22:
            meta["protocol"] = "SSH"
            if payload.startswith(b"SSH-"):
                meta["info"] = f"SSH Handshake {payload.decode('latin-1', errors='ignore').strip()[:50]}"

    def _inspect_udp_application_layers(self, packet: Any, meta: Dict[str, Any]):
        """Dissects DNS queries/answers and DHCP."""
        if packet.haslayer(DNS):
            meta["protocol"] = "DNS"
            dns = packet[DNS]
            qname = ""
            qtype = ""
            if dns.qdcount > 0 and dns.qd:
                qname = dns.qd.qname.decode("latin-1", errors="ignore").rstrip(".")
                qtype_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 5: "CNAME", 12: "PTR"}
                qtype = qtype_map.get(dns.qd.qtype, f"TYPE{dns.qd.qtype}")

            if dns.qr == 0:  # Query
                meta["info"] = f"DNS Query {qtype} {qname}"
            else:  # Response
                meta["info"] = f"DNS Response {qtype} {qname} (Answers={dns.ancount})"

            meta["details"]["dns_qr"] = dns.qr
            meta["details"]["dns_qname"] = qname
            meta["details"]["dns_qtype"] = qtype
            meta["details"]["dns_rcode"] = dns.rcode

        elif packet.haslayer(DHCP):
            meta["protocol"] = "DHCP"
            meta["info"] = "DHCP Message"

    def _extract_tls_sni(self, payload: bytes) -> Optional[str]:
        """Safely parses TLS ClientHello payload to extract the Server Name Indication (SNI)."""
        try:
            if len(payload) < 43 or payload[0] != 0x16:
                return None
            handshake_type = payload[5]
            if handshake_type != 1:  # Not ClientHello
                return None

            pos = 5 + 4 + 2 + 32  # Skip record header, handshake header, version, client_random
            if pos >= len(payload):
                return None

            # Skip session ID
            session_id_len = payload[pos]
            pos += 1 + session_id_len
            if pos + 2 > len(payload):
                return None

            # Skip Cipher Suites
            cipher_suites_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2 + cipher_suites_len
            if pos + 1 > len(payload):
                return None

            # Skip Compression methods
            compression_methods_len = payload[pos]
            pos += 1 + compression_methods_len
            if pos + 2 > len(payload):
                return None

            # Extensions length
            extensions_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + extensions_len

            while pos + 4 <= ext_end and pos + 4 <= len(payload):
                ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
                ext_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
                pos += 4
                if ext_type == 0:  # server_name extension
                    if pos + 2 <= len(payload):
                        name_list_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                        name_pos = pos + 2
                        if name_pos + 3 <= len(payload) and payload[name_pos] == 0:  # host_name
                            host_name_len = struct.unpack("!H", payload[name_pos + 1:name_pos + 3])[0]
                            sni_bytes = payload[name_pos + 3:name_pos + 3 + host_name_len]
                            return sni_bytes.decode("utf-8", errors="ignore")
                pos += ext_len
        except Exception:
            return None
        return None

    def parse_all(self, max_packets: Optional[int] = None) -> List[Dict[str, Any]]:
        """Parses the PCAP file and returns all packet records."""
        results: List[Dict[str, Any]] = []
        frame_num = 1
        with PcapReader(self.pcap_path) as reader:
            for packet in reader:
                try:
                    meta = self.parse_packet_metadata(packet, frame_num)
                    results.append(meta)
                    frame_num += 1
                    if max_packets and frame_num > max_packets:
                        break
                except Exception as e:
                    # Continue parsing remaining packets even if one corrupt frame fails
                    continue
        return results

    def parse_generator(self) -> Generator[Dict[str, Any], None, None]:
        """Streaming generator for large PCAPs to conserve memory."""
        frame_num = 1
        with PcapReader(self.pcap_path) as reader:
            for packet in reader:
                try:
                    meta = self.parse_packet_metadata(packet, frame_num)
                    yield meta
                    frame_num += 1
                except Exception:
                    continue


class PySharkParser:
    """Dissection engine using PyShark and TShark when available."""

    def __init__(self, pcap_path: str, tshark_path: Optional[str] = None):
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark library is not installed.")
        self.pcap_path = pcap_path
        self.tshark_path = tshark_path or find_tshark_path()

    def parse_summary(self, max_packets: int = 100) -> List[Dict[str, Any]]:
        """Extracts packet summaries using PyShark FileCapture."""
        cap_kwargs = {"tshark_path": self.tshark_path} if self.tshark_path else {}
        cap = pyshark.FileCapture(self.pcap_path, only_summaries=True, **cap_kwargs)
        summaries = []
        try:
            for i, pkt in enumerate(cap):
                if i >= max_packets:
                    break
                summaries.append({
                    "frame_num": int(pkt.no),
                    "timestamp": float(pkt.time),
                    "src_ip": pkt.source,
                    "dst_ip": pkt.destination,
                    "protocol": pkt.protocol,
                    "length": int(pkt.length),
                    "info": pkt.info
                })
        finally:
            cap.close()
        return summaries

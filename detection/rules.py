"""
NetSentinel - Intrusion Detection Rule Engine
Signature-based and behavioral heuristic detection for port scans, DoS floods, DNS tunneling, and cleartext credentials.
"""

import collections
import math
import time
from typing import Any, Dict, List, Optional, Set, Tuple


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon Entropy to detect encoded/encrypted data in domain names."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = collections.Counter(data.lower())
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class RuleEngine:
    """Evaluates network packets and flows against cybersecurity detection rules."""

    def __init__(self, port_scan_threshold: int = 8,
                 syn_flood_threshold: int = 15,
                 icmp_flood_threshold: int = 15,
                 dns_length_threshold: int = 45,
                 dns_entropy_threshold: float = 3.6):
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.icmp_flood_threshold = icmp_flood_threshold
        self.dns_length_threshold = dns_length_threshold
        self.dns_entropy_threshold = dns_entropy_threshold

    def evaluate_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Executes all rule checks across a collection of packets.
        Returns a list of structured security alert dictionaries.
        """
        alerts: List[Dict[str, Any]] = []

        # Tracking structures for stateful/heuristic checks
        src_scanned_ports: Dict[str, Set[int]] = collections.defaultdict(set)
        src_port_packet_refs: Dict[str, List[int]] = collections.defaultdict(list)
        src_syn_counts: Dict[str, int] = collections.defaultdict(int)
        src_ack_counts: Dict[str, int] = collections.defaultdict(int)
        src_icmp_counts: Dict[str, int] = collections.defaultdict(int)
        src_auth_failures: Dict[str, int] = collections.defaultdict(int)
        ip_mac_mappings: Dict[str, Set[str]] = collections.defaultdict(set)

        sensitive_ports = {21, 22, 23, 3389, 445, 1433, 3306, 5432}

        for pkt in packets:
            frame_num = pkt.get("frame_num", 0)
            ts = pkt.get("timestamp", time.time())
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            src_port = pkt.get("src_port")
            dst_port = pkt.get("dst_port")
            proto = pkt.get("protocol", "OTHER")
            flags = str(pkt.get("flags", "")).upper()
            details = pkt.get("details", {})

            # -------------------------------------------------------------
            # Rule 1: Stealth TCP Scans (NULL, FIN, XMAS scans)
            # -------------------------------------------------------------
            if proto == "TCP" and flags:
                # NULL scan: no flags set
                if flags in ["0", "NONE", ""]:
                    alerts.append({
                        "timestamp": ts,
                        "rule_id": "NET-SCAN-003",
                        "rule_name": "Stealth TCP NULL Scan Detected",
                        "severity": "HIGH",
                        "category": "Reconnaissance",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "TCP",
                        "description": f"Host {src_ip} sent TCP packet with no flags (NULL scan) to {dst_ip}:{dst_port}",
                        "evidence": {"frame_num": frame_num, "flags": flags, "mitre": "T1046"}
                    })
                # FIN scan: only FIN flag
                elif flags == "F":
                    alerts.append({
                        "timestamp": ts,
                        "rule_id": "NET-SCAN-003",
                        "rule_name": "Stealth TCP FIN Scan Detected",
                        "severity": "HIGH",
                        "category": "Reconnaissance",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "TCP",
                        "description": f"Host {src_ip} sent TCP FIN-only scan packet to {dst_ip}:{dst_port}",
                        "evidence": {"frame_num": frame_num, "flags": flags, "mitre": "T1046"}
                    })
                # XMAS scan: FIN, PSH, and URG all set
                elif "F" in flags and "P" in flags and "U" in flags:
                    alerts.append({
                        "timestamp": ts,
                        "rule_id": "NET-SCAN-003",
                        "rule_name": "Stealth TCP XMAS Scan Detected",
                        "severity": "HIGH",
                        "category": "Reconnaissance",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "TCP",
                        "description": f"Host {src_ip} sent TCP XMAS scan packet (FPU flags) to {dst_ip}:{dst_port}",
                        "evidence": {"frame_num": frame_num, "flags": flags, "mitre": "T1046"}
                    })

            # -------------------------------------------------------------
            # Rule 2: Cleartext Credentials (HTTP Basic Auth, FTP USER/PASS)
            # -------------------------------------------------------------
            if details.get("http_auth"):
                alerts.append({
                    "timestamp": ts,
                    "rule_id": "NET-DATA-001",
                    "rule_name": "Cleartext HTTP Credentials Detected",
                    "severity": "HIGH",
                    "category": "Credential Exposure",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "HTTP",
                    "description": f"Unencrypted HTTP Authorization header detected from {src_ip} to {dst_ip}:{dst_port}",
                    "evidence": {"frame_num": frame_num, "auth_header": details["http_auth"][:30] + "...", "mitre": "T1552"}
                })

            if details.get("ftp_cmd"):
                cmd = details["ftp_cmd"]
                alerts.append({
                    "timestamp": ts,
                    "rule_id": "NET-DATA-002",
                    "rule_name": "Cleartext FTP Authentication Command",
                    "severity": "MEDIUM",
                    "category": "Credential Exposure",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "FTP",
                    "description": f"Cleartext FTP credential transmission: {cmd.split()[0]} command sent to {dst_ip}:{dst_port}",
                    "evidence": {"frame_num": frame_num, "command": cmd.split()[0], "mitre": "T1552"}
                })

            # -------------------------------------------------------------
            # Rule 3: DNS Tunneling / Exfiltration Anomalies
            # -------------------------------------------------------------
            if proto == "DNS" and details.get("dns_qname"):
                qname = details["dns_qname"]
                qlen = len(qname)
                entropy = calculate_shannon_entropy(qname)
                if qlen >= self.dns_length_threshold and entropy >= self.dns_entropy_threshold:
                    alerts.append({
                        "timestamp": ts,
                        "rule_id": "NET-EXFIL-001",
                        "rule_name": "Potential DNS Tunneling / Exfiltration",
                        "severity": "CRITICAL",
                        "category": "Command & Control / Exfiltration",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "DNS",
                        "description": f"High-entropy anomalous DNS query length ({qlen} chars, entropy={entropy}): '{qname[:50]}...'",
                        "evidence": {"frame_num": frame_num, "query": qname, "entropy": entropy, "length": qlen, "mitre": "T1071.004"}
                    })

            # -------------------------------------------------------------
            # Aggregations for Heuristic / Volume rules
            # -------------------------------------------------------------
            if src_ip:
                # Track port scanning
                if dst_port and dst_port > 0:
                    src_scanned_ports[src_ip].add(dst_port)
                    src_port_packet_refs[src_ip].append(frame_num)

                # Track SYN flood
                if proto == "TCP":
                    if "S" in flags and "A" not in flags:
                        src_syn_counts[src_ip] += 1
                    if "A" in flags:
                        src_ack_counts[src_ip] += 1

                # Track ICMP flood
                if proto == "ICMP" and details.get("icmp_type") == 8:
                    src_icmp_counts[src_ip] += 1

                # Track failed connections to sensitive auth services
                if proto == "TCP" and dst_port in sensitive_ports:
                    if "R" in flags or ("S" in flags and "A" not in flags):
                        src_auth_failures[src_ip] += 1

            # ARP Poisoning tracking
            if proto == "ARP" and details.get("arp_op") == 2:  # is-at reply
                arp_ip = pkt.get("src_ip")
                arp_mac = details.get("arp_src_mac")
                if arp_ip and arp_mac:
                    ip_mac_mappings[arp_ip].add(arp_mac)

        # -------------------------------------------------------------
        # Rule 4: Horizontal Port Scan Threshold Alert
        # -------------------------------------------------------------
        for src_ip, ports in src_scanned_ports.items():
            if len(ports) >= self.port_scan_threshold:
                alerts.append({
                    "timestamp": packets[-1]["timestamp"] if packets else time.time(),
                    "rule_id": "NET-SCAN-001",
                    "rule_name": "Horizontal Port Scan Activity",
                    "severity": "HIGH",
                    "category": "Reconnaissance",
                    "src_ip": src_ip,
                    "dst_ip": "Multiple",
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "TCP/UDP",
                    "description": f"Source {src_ip} probed {len(ports)} unique ports ({sorted(list(ports))[:10]}...)",
                    "evidence": {
                        "ports_probed": len(ports),
                        "sample_ports": sorted(list(ports))[:15],
                        "packet_refs": src_port_packet_refs[src_ip][:10],
                        "mitre": "T1046"
                    }
                })

        # -------------------------------------------------------------
        # Rule 5: SYN Flood (Denial of Service)
        # -------------------------------------------------------------
        for src_ip, syn_count in src_syn_counts.items():
            ack_count = src_ack_counts.get(src_ip, 0)
            if syn_count >= self.syn_flood_threshold and (ack_count == 0 or (syn_count / (ack_count + 1)) > 5.0):
                alerts.append({
                    "timestamp": packets[-1]["timestamp"] if packets else time.time(),
                    "rule_id": "NET-DOS-001",
                    "rule_name": "TCP SYN Flood DoS Detected",
                    "severity": "CRITICAL",
                    "category": "Denial of Service",
                    "src_ip": src_ip,
                    "dst_ip": "Target Subnet",
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "TCP",
                    "description": f"High volume of unacknowledged SYN packets ({syn_count} SYNs vs {ack_count} ACKs) from {src_ip}",
                    "evidence": {"syn_count": syn_count, "ack_count": ack_count, "mitre": "T1498"}
                })

        # -------------------------------------------------------------
        # Rule 6: ICMP Echo Flood (Ping Flood)
        # -------------------------------------------------------------
        for src_ip, icmp_count in src_icmp_counts.items():
            if icmp_count >= self.icmp_flood_threshold:
                alerts.append({
                    "timestamp": packets[-1]["timestamp"] if packets else time.time(),
                    "rule_id": "NET-DOS-002",
                    "rule_name": "ICMP Echo Flood / Ping Sweep",
                    "severity": "MEDIUM",
                    "category": "Denial of Service",
                    "src_ip": src_ip,
                    "dst_ip": "Target Subnet",
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "ICMP",
                    "description": f"Excessive ICMP Echo requests ({icmp_count} echo requests) sent by {src_ip}",
                    "evidence": {"icmp_count": icmp_count, "mitre": "T1498"}
                })

        # -------------------------------------------------------------
        # Rule 7: Repeated Brute-Force Connection Attempts
        # -------------------------------------------------------------
        for src_ip, fail_count in src_auth_failures.items():
            if fail_count >= 10:
                alerts.append({
                    "timestamp": packets[-1]["timestamp"] if packets else time.time(),
                    "rule_id": "NET-AUTH-001",
                    "rule_name": "Authentication Port Brute-Force Activity",
                    "severity": "HIGH",
                    "category": "Credential Access",
                    "src_ip": src_ip,
                    "dst_ip": "Target Host",
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "TCP",
                    "description": f"Source {src_ip} made {fail_count} repeated connection attempts or resets against authentication services",
                    "evidence": {"attempts_count": fail_count, "mitre": "T1110"}
                })

        # -------------------------------------------------------------
        # Rule 8: ARP Spoofing / Poisoning Conflict
        # -------------------------------------------------------------
        for arp_ip, macs in ip_mac_mappings.items():
            if len(macs) > 1:
                alerts.append({
                    "timestamp": packets[-1]["timestamp"] if packets else time.time(),
                    "rule_id": "NET-MITM-001",
                    "rule_name": "ARP Poisoning / IP Conflict Detected",
                    "severity": "CRITICAL",
                    "category": "Man-In-The-Middle",
                    "src_ip": arp_ip,
                    "dst_ip": "Broadcast",
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "ARP",
                    "description": f"IP address {arp_ip} is claimed by multiple MAC addresses: {list(macs)}",
                    "evidence": {"ip": arp_ip, "conflicting_macs": list(macs), "mitre": "T1557.002"}
                })

        return alerts

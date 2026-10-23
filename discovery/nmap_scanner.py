"""
NetSentinel - Network Reconnaissance & Exposure Assessment
Authorized host discovery, port scanning, service identification, and risk assessment using Nmap and native socket fallback.
"""

import json
import logging
import os
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("NetSentinel.Recon")

# Well-known service vulnerability risk database for exposure assessment
SERVICE_RISK_MAP: Dict[int, Dict[str, Any]] = {
    21: {"service": "FTP", "risk": "MEDIUM", "desc": "Cleartext file transfer protocol; vulnerable to credential sniffing and anonymous access."},
    22: {"service": "SSH", "risk": "LOW", "desc": "Encrypted remote terminal; ensure strong key authentication and disable root password login."},
    23: {"service": "Telnet", "risk": "CRITICAL", "desc": "Unencrypted legacy management protocol; transmits passwords in cleartext. Replace immediately with SSH."},
    25: {"service": "SMTP", "risk": "MEDIUM", "desc": "Mail transfer protocol; verify open relay protection and TLS enforcement."},
    53: {"service": "DNS", "risk": "LOW", "desc": "Domain name resolution; check for open recursion and DNS amplification vectors."},
    80: {"service": "HTTP", "risk": "MEDIUM", "desc": "Unencrypted web traffic; sensitive data and session cookies should be redirected to HTTPS."},
    110: {"service": "POP3", "risk": "MEDIUM", "desc": "Cleartext email retrieval; upgrade to POP3S over TLS (port 995)."},
    135: {"service": "MSRPC", "risk": "HIGH", "desc": "Microsoft RPC endpoint mapper; high-value target for lateral movement and exploits."},
    139: {"service": "NetBIOS", "risk": "HIGH", "desc": "Legacy Windows file sharing; vulnerable to user enumeration and relay attacks."},
    143: {"service": "IMAP", "risk": "MEDIUM", "desc": "Cleartext email access; migrate to IMAPS (port 993)."},
    443: {"service": "HTTPS", "risk": "LOW", "desc": "Encrypted TLS web service; verify TLS 1.2+ configuration and certificate validity."},
    445: {"service": "SMB", "risk": "CRITICAL", "desc": "Server Message Block; historic vector for ransomware (EternalBlue, WannaCry). Do not expose to public networks."},
    1433: {"service": "MSSQL", "risk": "HIGH", "desc": "Microsoft SQL Server database; should not be exposed externally. Enforce strong authentication."},
    3306: {"service": "MySQL", "risk": "HIGH", "desc": "MySQL database; risk of brute-force and remote query execution. Restrict to internal bind addresses."},
    3389: {"service": "RDP", "risk": "HIGH", "desc": "Remote Desktop Protocol; high-priority target for brute-force and ransomware entry. Require MFA or VPN."},
    5432: {"service": "PostgreSQL", "risk": "HIGH", "desc": "PostgreSQL database port; restrict access to authorized application servers only."},
    6379: {"service": "Redis", "risk": "CRITICAL", "desc": "In-memory datastore; frequently deployed without authentication. Critical risk of remote code execution."},
    8080: {"service": "HTTP-Proxy", "risk": "MEDIUM", "desc": "Alternate HTTP / web proxy port; check for exposed administrative dashboards."},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "desc": "NoSQL database; high risk of unauthorized data exposure if authentication is disabled."}
}


class NmapScanner:
    """Manages network discovery scans and parses structured results."""

    def __init__(self, nmap_executable: Optional[str] = None):
        self.nmap_path = nmap_executable or shutil.which("nmap")
        if not self.nmap_path:
            # Check common Windows paths
            candidates = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ]
            for c in candidates:
                if os.path.isfile(c):
                    self.nmap_path = c
                    break

    @property
    def is_available(self) -> bool:
        return self.nmap_path is not None and os.path.exists(self.nmap_path)

    def scan(self, target: str, scan_type: str = "quick", ports: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes an authorized network scan against target.
        Supported scan types: 'quick', 'syn', 'service', 'full', 'ping'.
        Falls back to native Python socket scanner if Nmap CLI is unavailable.
        """
        start_time = time.time()

        if not self.is_available:
            logger.warning("Nmap executable not found. Running Native Python Socket Scanner.")
            return self._native_socket_scan(target, ports)

        # Build Nmap command line arguments
        cmd = [self.nmap_path, "-oX", "-"]  # Output XML to stdout

        if scan_type == "ping":
            cmd.extend(["-sn"])
        elif scan_type == "quick":
            cmd.extend(["-F", "-T4"])
        elif scan_type == "syn":
            # Note: SYN scan (-sS) requires raw socket privileges. If not admin, fallback to connect (-sT)
            cmd.extend(["-sT", "-T4"])
        elif scan_type == "service":
            cmd.extend(["-sV", "-T4"])
        elif scan_type == "full":
            cmd.extend(["-sV", "-p", "1-1000", "-T4"])

        if ports and scan_type != "ping":
            cmd.extend(["-p", ports])

        cmd.append(target)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0 and not result.stdout:
                logger.error(f"Nmap error: {result.stderr}")
                return self._native_socket_scan(target, ports)

            parsed = self._parse_nmap_xml(result.stdout, target, scan_type)
            parsed["duration"] = round(time.time() - start_time, 2)
            parsed["raw_output"] = result.stdout[:2000]
            return parsed
        except subprocess.TimeoutExpired:
            return {
                "target": target,
                "status": "TIMEOUT",
                "error": "Scan timed out after 120 seconds",
                "open_ports_count": 0,
                "results": {"hosts": []}
            }
        except Exception as e:
            logger.error(f"Scan failed with exception: {e}. Falling back to socket scan.")
            return self._native_socket_scan(target, ports)

    def _parse_nmap_xml(self, xml_content: str, target: str, scan_type: str) -> Dict[str, Any]:
        """Parses Nmap XML output into a clean, structured schema with risk scores."""
        hosts_data = []
        total_open_ports = 0

        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                status_elem = host.find("status")
                if status_elem is not None and status_elem.get("state") != "up":
                    continue

                # IP addresses
                ip_addr = ""
                mac_addr = ""
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip_addr = addr.get("addr", "")
                    elif addr.get("addrtype") == "mac":
                        mac_addr = addr.get("addr", "")

                host_record: Dict[str, Any] = {
                    "ip": ip_addr or target,
                    "mac": mac_addr,
                    "status": "UP",
                    "ports": [],
                    "exposure_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                }

                # Ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_id = int(port.get("portid", 0))
                        proto = port.get("protocol", "tcp")
                        state_elem = port.find("state")
                        state = state_elem.get("state") if state_elem is not None else "unknown"

                        if state == "open":
                            total_open_ports += 1
                            svc_elem = port.find("service")
                            svc_name = svc_elem.get("name", "unknown") if svc_elem is not None else "unknown"
                            svc_product = svc_elem.get("product", "") if svc_elem is not None else ""
                            svc_version = svc_elem.get("version", "") if svc_elem is not None else ""

                            # Assess risk
                            risk_info = SERVICE_RISK_MAP.get(port_id, {
                                "service": svc_name,
                                "risk": "LOW",
                                "desc": f"Standard service {svc_name} on port {port_id}"
                            })

                            risk_level = risk_info["risk"]
                            host_record["exposure_summary"][risk_level.lower()] += 1

                            host_record["ports"].append({
                                "port": port_id,
                                "protocol": proto,
                                "state": state,
                                "service": svc_name,
                                "product": svc_product,
                                "version": svc_version,
                                "risk_level": risk_level,
                                "remediation": risk_info["desc"]
                            })

                hosts_data.append(host_record)

        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")

        return {
            "timestamp": time.time(),
            "target": target,
            "scan_type": scan_type,
            "status": "COMPLETED",
            "scanner": "Nmap 7.x",
            "open_ports_count": total_open_ports,
            "results": {"hosts": hosts_data}
        }

    def _native_socket_scan(self, target: str, ports_str: Optional[str] = None) -> Dict[str, Any]:
        """Pure Python concurrent TCP socket scanner used when Nmap is unavailable."""
        start_time = time.time()
        port_list = []
        if ports_str:
            for p in ports_str.split(","):
                p = p.strip()
                if "-" in p:
                    start_p, end_p = map(int, p.split("-"))
                    port_list.extend(range(start_p, min(end_p + 1, 65535)))
                elif p.isdigit():
                    port_list.append(int(p))
        else:
            # Common top reconnaissance ports
            port_list = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 27017]

        open_ports = []
        exposure_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        def check_port(port: int):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        banner = ""
                        try:
                            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = s.recv(128).decode("latin-1", errors="ignore").split("\r\n")[0]
                        except Exception:
                            pass

                        risk_info = SERVICE_RISK_MAP.get(port, {
                            "service": f"port-{port}",
                            "risk": "LOW",
                            "desc": f"Open port {port}"
                        })
                        return {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": risk_info["service"],
                            "product": banner[:40],
                            "version": "",
                            "risk_level": risk_info["risk"],
                            "remediation": risk_info["desc"]
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(check_port, port_list)
            for res in results:
                if res:
                    open_ports.append(res)
                    exposure_summary[res["risk_level"].lower()] += 1

        return {
            "timestamp": time.time(),
            "target": target,
            "scan_type": "native_socket",
            "status": "COMPLETED",
            "scanner": "NetSentinel Native Socket Engine",
            "duration": round(time.time() - start_time, 2),
            "open_ports_count": len(open_ports),
            "results": {
                "hosts": [{
                    "ip": target,
                    "mac": "",
                    "status": "UP" if open_ports else "UNKNOWN",
                    "ports": open_ports,
                    "exposure_summary": exposure_summary
                }]
            }
        }

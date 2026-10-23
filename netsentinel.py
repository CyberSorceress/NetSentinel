#!/usr/bin/env python3
"""
NetSentinel - Intelligent Network Security Monitoring and Intrusion Detection System
Unified Command-Line Interface (CLI)

Usage:
    python netsentinel.py generate-samples
    python netsentinel.py parse <pcap_file>
    python netsentinel.py detect <pcap_file>
    python netsentinel.py scan <target> [--type quick|service|full]
    python netsentinel.py train-ml <pcap_file>
    python netsentinel.py dashboard [--port 5000]
    python netsentinel.py live [--iface eth0] [--filter "tcp port 80"]
"""

import argparse
import json
import os
import sys
import time

# Ensure NetSentinel packages are resolvable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from analysis.flow_features import FlowAggregator
from capture.live_capture import LiveCaptureMonitor
from capture.pcap_parser import PacketParser
from database.models import DatabaseManager, get_db
from detection.anomaly_detector import NetworkAnomalyDetector
from detection.rules import RuleEngine
from discovery.nmap_scanner import NmapScanner
from sample_pcaps.generate_pcaps import generate_all_samples

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None


def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║   _   _      _   ____             _   _            _             ║
    ║  | \ | | ___| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |            ║
    ║  |  \| |/ _ \ __\___ \ / _ \ '_ \| __| | '_ \ / _ \ |            ║
    ║  | |\  |  __/ |_ ___) |  __/ | | | |_| | | | |  __/ |            ║
    ║  |_| \_|\___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|            ║
    ║                                                                  ║
    ║  Intelligent Network Security Monitoring & Intrusion Detection   ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    if HAS_RICH:
        console.print(f"[bold cyan]{banner}[/bold cyan]")
    else:
        print(banner)


def cmd_generate_samples(args):
    """Generates synthetic normal and attack PCAP datasets."""
    out_dir = os.path.join(BASE_DIR, "sample_pcaps")
    print(f"[*] Generating sample PCAPs into {out_dir}...")
    files = generate_all_samples(out_dir)
    print("[+] Successfully created datasets:")
    for name, path in files.items():
        size = os.path.getsize(path)
        print(f"    - {name:<20}: {os.path.basename(path)} ({size} bytes)")


def cmd_parse(args):
    """Parses a PCAP file and prints network packet and protocol statistics."""
    pcap_path = args.pcap_file
    if not os.path.exists(pcap_path):
        print(f"[-] File not found: {pcap_path}")
        return

    print(f"[*] Parsing capture file: {pcap_path} ...")
    parser = PacketParser(pcap_path)
    packets = parser.parse_all(max_packets=args.max_packets)

    print(f"[+] Parsed {len(packets)} packets.")
    if HAS_RICH:
        table = Table(title=f"Sample Packets from {os.path.basename(pcap_path)}")
        table.add_column("Frame", justify="right", style="cyan")
        table.add_column("Proto", style="magenta")
        table.add_column("Source", style="green")
        table.add_column("Destination", style="yellow")
        table.add_column("Flags", style="bold red")
        table.add_column("Info", style="white")

        for p in packets[:15]:
            src = f"{p['src_ip'] or 'N/A'}:{p['src_port']}" if p.get("src_port") else str(p.get("src_ip") or "N/A")
            dst = f"{p['dst_ip'] or 'N/A'}:{p['dst_port']}" if p.get("dst_port") else str(p.get("dst_ip") or "N/A")
            table.add_row(str(p["frame_num"]), p["protocol"], src, dst, p["flags"] or "-", p["info"])
        console.print(table)
    else:
        for p in packets[:15]:
            print(f"  #{p['frame_num']:<4} {p['protocol']:<6} {str(p.get('src_ip')):<15} -> {str(p.get('dst_ip')):<15} [{p['flags']}] {p['info']}")


def cmd_detect(args):
    """Parses a PCAP, runs rule engine and ML anomaly detector, and outputs alerts."""
    pcap_path = args.pcap_file
    if not os.path.exists(pcap_path):
        print(f"[-] File not found: {pcap_path}")
        return

    print(f"[*] Ingesting and evaluating {pcap_path} ...")
    parser = PacketParser(pcap_path)
    packets = parser.parse_all()

    # Rule evaluation
    rule_engine = RuleEngine()
    rule_alerts = rule_engine.evaluate_packets(packets)

    # Flow reconstruction & ML evaluation
    aggregator = FlowAggregator()
    aggregator.process_packets(packets)
    df_flows = aggregator.to_dataframe()

    ml_detector = NetworkAnomalyDetector()
    if not df_flows.empty:
        df_analyzed = ml_detector.predict_flows(df_flows)
        ml_alerts = ml_detector.generate_alerts_from_anomalies(df_analyzed)
    else:
        ml_alerts = []

    all_alerts = rule_alerts + ml_alerts
    print(f"\n[+] Analysis Complete: {len(packets)} packets, {len(df_flows)} sessions, {len(all_alerts)} alerts found.")

    if HAS_RICH and all_alerts:
        table = Table(title="Detected Security Incidents")
        table.add_column("Severity", style="bold")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Threat Name", style="white")
        table.add_column("Category", style="yellow")
        table.add_column("Attacker", style="red")
        table.add_column("Target", style="green")

        for a in all_alerts:
            sev_style = "red" if a["severity"] in ["CRITICAL", "HIGH"] else "yellow"
            table.add_row(
                f"[{sev_style}]{a['severity']}[/{sev_style}]",
                a["rule_id"],
                a["rule_name"],
                a["category"],
                str(a["src_ip"]),
                f"{a['dst_ip']}:{a.get('dst_port') or '*'}"
            )
        console.print(table)
    elif all_alerts:
        for a in all_alerts:
            print(f"  [{a['severity']}] {a['rule_name']} ({a['rule_id']}) from {a['src_ip']} -> {a['description']}")
    else:
        print("  [OK] No suspicious intrusions or anomalies detected.")


def cmd_scan(args):
    """Runs an authorized reconnaissance scan against target."""
    scanner = NmapScanner()
    print(f"[*] Starting {args.type} scan on target: {args.target} ...")
    results = scanner.scan(args.target, scan_type=args.type, ports=args.ports)
    print(f"[+] Scan completed in {results.get('duration', 0)}s ({results.get('open_ports_count', 0)} open ports).")

    hosts = results.get("results", {}).get("hosts", [])
    for host in hosts:
        print(f"\n  Host: {host['ip']} (Status: {host['status']})")
        for p in host.get("ports", []):
            risk = p.get("risk_level", "LOW")
            print(f"    - Port {p['port']}/{p['protocol']}: {p['service']} ({p['product']} {p['version']}) [Risk: {risk}]")
            if p.get("remediation"):
                print(f"      Recommendation: {p['remediation']}")


def cmd_train_ml(args):
    """Trains the Isolation Forest model on baseline PCAP flows."""
    pcap_path = args.pcap_file
    if not os.path.exists(pcap_path):
        print(f"[-] File not found: {pcap_path}")
        return

    print(f"[*] Extracting baseline flow features from: {pcap_path} ...")
    parser = PacketParser(pcap_path)
    packets = parser.parse_all()

    aggregator = FlowAggregator()
    aggregator.process_packets(packets)
    df_flows = aggregator.to_dataframe()

    if len(df_flows) < 5:
        print(f"[-] Need at least 5 flow conversations for training (found {len(df_flows)}).")
        return

    detector = NetworkAnomalyDetector()
    res = detector.fit(df_flows)
    print(f"[+] Successfully trained Isolation Forest on {res['samples']} sessions.")
    print(f"[+] Model persisted to: {detector.model_path}")


def cmd_dashboard(args):
    """Starts the Flask centralized security dashboard."""
    from dashboard.app import app
    print(f"[*] Starting NetSentinel SOC Dashboard on http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, debug=False)


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NetSentinel - Network Security Monitoring & IDS")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # generate-samples
    subparsers.add_parser("generate-samples", help="Generate synthetic test PCAP datasets")

    # parse
    parse_p = subparsers.add_parser("parse", help="Parse and inspect a PCAP file")
    parse_p.add_argument("pcap_file", help="Path to PCAP file")
    parse_p.add_argument("--max-packets", type=int, default=100, help="Maximum packets to display")

    # detect
    detect_p = subparsers.add_parser("detect", help="Run rule and ML intrusion detection on a PCAP")
    detect_p.add_argument("pcap_file", help="Path to PCAP file")

    # scan
    scan_p = subparsers.add_parser("scan", help="Run authorized reconnaissance scan")
    scan_p.add_argument("target", help="IP address or domain to scan (e.g. 127.0.0.1)")
    scan_p.add_argument("--type", choices=["quick", "service", "syn", "full", "ping"], default="quick", help="Scan type")
    scan_p.add_argument("--ports", help="Port range (e.g. 21,22,80,443)")

    # train-ml
    train_p = subparsers.add_parser("train-ml", help="Train Isolation Forest on normal baseline traffic")
    train_p.add_argument("pcap_file", help="Baseline PCAP file")

    # dashboard
    dash_p = subparsers.add_parser("dashboard", help="Launch Flask web dashboard")
    dash_p.add_argument("--port", type=int, default=5000, help="Web server port")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    cmd_map = {
        "generate-samples": cmd_generate_samples,
        "parse": cmd_parse,
        "detect": cmd_detect,
        "scan": cmd_scan,
        "train-ml": cmd_train_ml,
        "dashboard": cmd_dashboard,
    }
    cmd_func = cmd_map.get(args.command)
    if cmd_func:
        cmd_func(args)


if __name__ == "__main__":
    main()

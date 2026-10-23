"""
NetSentinel - Comprehensive Test Suite
Verifies database persistence, PCAP parsing, flow extraction, rule detection, ML anomaly scoring, and Flask web endpoints.
"""

import os
import sys
import tempfile
import unittest

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import pandas as pd
from analysis.flow_features import FlowAggregator, FlowSession
from capture.pcap_parser import PacketParser
from database.models import DatabaseManager
from detection.anomaly_detector import NetworkAnomalyDetector
from detection.rules import RuleEngine, calculate_shannon_entropy
from discovery.nmap_scanner import NmapScanner
from sample_pcaps.generate_pcaps import (
    generate_cleartext_creds_pcap,
    generate_dns_tunneling_pcap,
    generate_normal_traffic_pcap,
    generate_port_scan_pcap,
    generate_syn_flood_pcap,
)


class TestNetSentinelDatabase(unittest.TestCase):
    """Tests SQLite database CRUD, transactions, and metrics aggregation."""

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db = DatabaseManager(self.temp_db_path)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_packets_insert_and_query(self):
        sample_pkts = [
            {
                "timestamp": 1000.0,
                "frame_num": 1,
                "src_ip": "192.168.1.10",
                "dst_ip": "1.1.1.1",
                "src_port": 50000,
                "dst_port": 53,
                "protocol": "DNS",
                "length": 64,
                "flags": "",
                "info": "DNS Query A google.com",
            },
            {
                "timestamp": 1000.1,
                "frame_num": 2,
                "src_ip": "1.1.1.1",
                "dst_ip": "192.168.1.10",
                "src_port": 53,
                "dst_port": 50000,
                "protocol": "DNS",
                "length": 80,
                "flags": "",
                "info": "DNS Response A google.com",
            }
        ]
        count = self.db.insert_packets(sample_pkts)
        self.assertEqual(count, 2)

        fetched = self.db.get_packets(limit=10)
        self.assertEqual(len(fetched), 2)
        self.assertEqual(fetched[0]["protocol"], "DNS")

    def test_alerts_and_acknowledgement(self):
        alert_data = {
            "timestamp": 2000.0,
            "rule_id": "NET-SCAN-001",
            "rule_name": "Horizontal Port Scan Activity",
            "severity": "HIGH",
            "category": "Reconnaissance",
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.1",
            "src_port": 45000,
            "dst_port": 80,
            "protocol": "TCP",
            "description": "Port scan probing multiple ports",
            "evidence": {"probed_ports": 20}
        }
        alert_id = self.db.insert_alert(alert_data)
        self.assertGreater(alert_id, 0)

        alerts = self.db.get_alerts(severity="HIGH")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["acknowledged"], 0)

        success = self.db.acknowledge_alert(alert_id, 1)
        self.assertTrue(success)
        updated = self.db.get_alert_by_id(alert_id)
        self.assertEqual(updated["acknowledged"], 1)

    def test_dashboard_summary(self):
        summary = self.db.get_dashboard_summary()
        self.assertIn("total_packets", summary)
        self.assertIn("total_flows", summary)
        self.assertIn("total_alerts", summary)
        self.assertIn("critical_alerts", summary)


class TestPacketParsingAndFeatures(unittest.TestCase):
    """Tests Scapy parsing, flow aggregation, and TCP state tracking."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.normal_pcap = os.path.join(cls.temp_dir, "normal.pcap")
        generate_normal_traffic_pcap(cls.normal_pcap)

    def test_pcap_parsing(self):
        parser = PacketParser(self.normal_pcap)
        packets = parser.parse_all()
        self.assertGreater(len(packets), 5)

        # Check protocols present
        protos = {p["protocol"] for p in packets}
        self.assertIn("ARP", protos)
        self.assertIn("DNS", protos)
        self.assertIn("TCP", protos)
        self.assertIn("ICMP", protos)

    def test_flow_aggregation(self):
        parser = PacketParser(self.normal_pcap)
        packets = parser.parse_all()

        agg = FlowAggregator()
        agg.process_packets(packets)
        df_flows = agg.to_dataframe()

        self.assertFalse(df_flows.empty)
        self.assertIn("duration", df_flows.columns)
        self.assertIn("total_packets", df_flows.columns)
        self.assertIn("packet_rate", df_flows.columns)
        self.assertIn("flow_state", df_flows.columns)

        # Confirm HTTP TCP flow reached ESTABLISHED
        tcp_flows = [f for f in agg.flows.values() if f.protocol == "TCP"]
        self.assertGreater(len(tcp_flows), 0)
        self.assertTrue(any(f.flow_state in ["ESTABLISHED", "CLOSED"] for f in tcp_flows))


class TestRuleEngineDetections(unittest.TestCase):
    """Tests intrusion detection rules for port scan, SYN flood, DNS tunneling, and cleartext auth."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.scan_pcap = os.path.join(cls.temp_dir, "scan.pcap")
        cls.flood_pcap = os.path.join(cls.temp_dir, "flood.pcap")
        cls.dns_pcap = os.path.join(cls.temp_dir, "dns.pcap")
        cls.creds_pcap = os.path.join(cls.temp_dir, "creds.pcap")

        generate_port_scan_pcap(cls.scan_pcap)
        generate_syn_flood_pcap(cls.flood_pcap)
        generate_dns_tunneling_pcap(cls.dns_pcap)
        generate_cleartext_creds_pcap(cls.creds_pcap)

    def test_port_scan_detection(self):
        parser = PacketParser(self.scan_pcap)
        packets = parser.parse_all()

        engine = RuleEngine()
        alerts = engine.evaluate_packets(packets)

        rule_ids = {a["rule_id"] for a in alerts}
        self.assertIn("NET-SCAN-001", rule_ids)  # Horizontal port scan
        self.assertIn("NET-SCAN-003", rule_ids)  # Stealth scan (NULL / XMAS)

    def test_syn_flood_detection(self):
        parser = PacketParser(self.flood_pcap)
        packets = parser.parse_all()

        engine = RuleEngine(syn_flood_threshold=10)
        alerts = engine.evaluate_packets(packets)

        rule_ids = {a["rule_id"] for a in alerts}
        self.assertIn("NET-DOS-001", rule_ids)  # SYN Flood DoS

    def test_dns_tunneling_detection(self):
        parser = PacketParser(self.dns_pcap)
        packets = parser.parse_all()

        engine = RuleEngine()
        alerts = engine.evaluate_packets(packets)

        rule_ids = {a["rule_id"] for a in alerts}
        self.assertIn("NET-EXFIL-001", rule_ids)  # DNS Exfiltration

    def test_cleartext_credentials_detection(self):
        parser = PacketParser(self.creds_pcap)
        packets = parser.parse_all()

        engine = RuleEngine()
        alerts = engine.evaluate_packets(packets)

        rule_ids = {a["rule_id"] for a in alerts}
        self.assertIn("NET-DATA-001", rule_ids)  # HTTP Basic Auth
        self.assertIn("NET-DATA-002", rule_ids)  # FTP cleartext USER/PASS


class TestMachineLearningAnomalyDetector(unittest.TestCase):
    """Tests Isolation Forest flow training and inference."""

    def test_isolation_forest_pipeline(self):
        # Create synthetic baseline flows
        baseline_rows = []
        for i in range(25):
            baseline_rows.append({
                "duration": 5.0 + (i * 0.1),
                "total_packets": 20 + i,
                "total_bytes": 1500 + (i * 50),
                "packet_rate": 4.0,
                "byte_rate": 300.0,
                "avg_packet_size": 75.0,
                "syn_ratio": 0.05,
                "rst_ratio": 0.0,
                "ack_ratio": 0.9,
                "iat_mean": 0.25,
                "iat_std": 0.05,
                "unique_dst_ports": 1,
            })
        df_normal = pd.DataFrame(baseline_rows)

        detector = NetworkAnomalyDetector(contamination=0.1)
        train_res = detector.fit(df_normal)
        self.assertEqual(train_res["status"], "trained")

        # Test extreme outlier (SYN flood or port scan session)
        outlier_flow = pd.DataFrame([{
            "duration": 0.1,
            "total_packets": 500,
            "total_bytes": 25000,
            "packet_rate": 5000.0,  # Massive packet spike
            "byte_rate": 250000.0,
            "avg_packet_size": 50.0,
            "syn_ratio": 1.0,        # 100% SYN
            "rst_ratio": 0.0,
            "ack_ratio": 0.0,
            "iat_mean": 0.0002,
            "iat_std": 0.00001,
            "unique_dst_ports": 45,  # 45 ports
        }])

        df_scored = detector.predict_flows(outlier_flow)
        self.assertTrue(df_scored["is_anomaly"].iloc[0])
        self.assertGreater(df_scored["anomaly_score"].iloc[0], 0.5)


class TestDashboardFlaskRoutes(unittest.TestCase):
    """Tests Flask web routes and APIs."""

    def setUp(self):
        from dashboard.app import app
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_home_page(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"NetSentinel", res.data)

    def test_packets_page(self):
        res = self.client.get("/packets")
        self.assertEqual(res.status_code, 200)

    def test_flows_page(self):
        res = self.client.get("/flows")
        self.assertEqual(res.status_code, 200)

    def test_alerts_page(self):
        res = self.client.get("/alerts")
        self.assertEqual(res.status_code, 200)

    def test_scans_page(self):
        res = self.client.get("/scans")
        self.assertEqual(res.status_code, 200)

    def test_report_page(self):
        res = self.client.get("/report")
        self.assertEqual(res.status_code, 200)

    def test_api_summary(self):
        res = self.client.get("/api/summary")
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertIn("total_packets", json_data)

    def test_export_alerts_csv(self):
        res = self.client.get("/api/export/alerts.csv")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")


if __name__ == "__main__":
    unittest.main()

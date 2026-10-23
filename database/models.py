"""
NetSentinel - Database Layer
Thread-safe SQLite storage for packets, flows, security alerts, reconnaissance scans, and audit events.
"""

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class DatabaseManager:
    """Manages SQLite database connections and CRUD operations for NetSentinel."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "netsentinel.db")
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for high-concurrency read/write performance
            self._local.conn.execute("PRAGMA journal_mode=WAL;")
            self._local.conn.execute("PRAGMA synchronous=NORMAL;")
        return self._local.conn

    def _init_db(self):
        """Creates the required tables and indexes if they do not exist."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            frame_num INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            length INTEGER,
            flags TEXT,
            info TEXT,
            payload_hex TEXT,
            pcap_source TEXT
        );

        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_key TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            start_time REAL NOT NULL,
            end_time REAL NOT NULL,
            duration REAL NOT NULL,
            total_packets INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            fwd_packets INTEGER DEFAULT 0,
            bwd_packets INTEGER DEFAULT 0,
            syn_count INTEGER DEFAULT 0,
            rst_count INTEGER DEFAULT 0,
            flow_state TEXT DEFAULT 'UNKNOWN',
            is_anomaly INTEGER DEFAULT 0,
            anomaly_score REAL DEFAULT 0.0,
            features_json TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
            category TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            description TEXT NOT NULL,
            evidence TEXT,
            acknowledged INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            open_ports_count INTEGER DEFAULT 0,
            results_json TEXT,
            raw_output TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);

        CREATE INDEX IF NOT EXISTS idx_flows_flow_key ON flows(flow_key);
        CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
        CREATE INDEX IF NOT EXISTS idx_flows_is_anomaly ON flows(is_anomaly);

        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
        """)
        conn.commit()

    # ------------------ Packets Operations ------------------

    def insert_packets(self, packets_data: List[Dict[str, Any]]) -> int:
        """Batch inserts packet records."""
        if not packets_data:
            return 0
        conn = self._get_connection()
        cursor = conn.cursor()
        query = """
        INSERT INTO packets (
            timestamp, frame_num, src_ip, dst_ip, src_port, dst_port,
            protocol, length, flags, info, payload_hex, pcap_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        records = [
            (
                p.get("timestamp", time.time()),
                p.get("frame_num", 0),
                p.get("src_ip"),
                p.get("dst_ip"),
                p.get("src_port"),
                p.get("dst_port"),
                p.get("protocol", "OTHER"),
                p.get("length", 0),
                p.get("flags", ""),
                p.get("info", ""),
                p.get("payload_hex", ""),
                p.get("pcap_source", "")
            )
            for p in packets_data
        ]
        cursor.executemany(query, records)
        conn.commit()
        return len(records)

    def get_packets(self, limit: int = 100, offset: int = 0, protocol: Optional[str] = None,
                    ip_filter: Optional[str] = None, pcap_source: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves paginated packets with optional filtering."""
        conn = self._get_connection()
        cursor = conn.cursor()
        clauses = []
        params: List[Any] = []

        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol.upper())
        if ip_filter:
            clauses.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
            params.extend([f"%{ip_filter}%", f"%{ip_filter}%"])
        if pcap_source:
            clauses.append("pcap_source = ?")
            params.append(pcap_source)

        where_stmt = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
        SELECT id, timestamp, frame_num, src_ip, dst_ip, src_port, dst_port,
               protocol, length, flags, info, pcap_source
        FROM packets
        {where_stmt}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_packet_by_id(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a single packet including its raw payload."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM packets WHERE id = ?", (packet_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    # ------------------ Flows Operations ------------------

    def insert_flows(self, flows_data: List[Dict[str, Any]]) -> int:
        """Batch inserts flow records."""
        if not flows_data:
            return 0
        conn = self._get_connection()
        cursor = conn.cursor()
        query = """
        INSERT INTO flows (
            flow_key, src_ip, dst_ip, src_port, dst_port, protocol,
            start_time, end_time, duration, total_packets, total_bytes,
            fwd_packets, bwd_packets, syn_count, rst_count, flow_state,
            is_anomaly, anomaly_score, features_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        records = [
            (
                f.get("flow_key", ""),
                f.get("src_ip", ""),
                f.get("dst_ip", ""),
                f.get("src_port", 0),
                f.get("dst_port", 0),
                f.get("protocol", "TCP"),
                f.get("start_time", 0.0),
                f.get("end_time", 0.0),
                f.get("duration", 0.0),
                f.get("total_packets", 0),
                f.get("total_bytes", 0),
                f.get("fwd_packets", 0),
                f.get("bwd_packets", 0),
                f.get("syn_count", 0),
                f.get("rst_count", 0),
                f.get("flow_state", "UNKNOWN"),
                1 if f.get("is_anomaly") else 0,
                f.get("anomaly_score", 0.0),
                json.dumps(f.get("features", {})) if isinstance(f.get("features"), dict) else str(f.get("features_json", "{}"))
            )
            for f in flows_data
        ]
        cursor.executemany(query, records)
        conn.commit()
        return len(records)

    def get_flows(self, limit: int = 100, offset: int = 0, anomaly_only: bool = False) -> List[Dict[str, Any]]:
        """Retrieves network flow statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()
        where_stmt = "WHERE is_anomaly = 1" if anomaly_only else ""
        query = f"""
        SELECT * FROM flows
        {where_stmt}
        ORDER BY start_time DESC
        LIMIT ? OFFSET ?
        """
        cursor.execute(query, (limit, offset))
        rows = cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["features"] = json.loads(d.get("features_json") or "{}")
            except Exception:
                d["features"] = {}
            result.append(d)
        return result

    def update_flow_anomaly(self, flow_id: int, is_anomaly: bool, anomaly_score: float):
        """Updates anomaly status for a specific flow."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        UPDATE flows
        SET is_anomaly = ?, anomaly_score = ?
        WHERE id = ?
        """, (1 if is_anomaly else 0, anomaly_score, flow_id))
        conn.commit()

    # ------------------ Alerts Operations ------------------

    def insert_alert(self, alert: Dict[str, Any]) -> int:
        """Inserts a new security alert."""
        conn = self._get_connection()
        cursor = conn.cursor()
        query = """
        INSERT INTO alerts (
            timestamp, rule_id, rule_name, severity, category,
            src_ip, dst_ip, src_port, dst_port, protocol,
            description, evidence, acknowledged
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        evidence_str = (
            json.dumps(alert.get("evidence", {}))
            if isinstance(alert.get("evidence"), (dict, list))
            else str(alert.get("evidence", ""))
        )
        cursor.execute(query, (
            alert.get("timestamp", time.time()),
            alert.get("rule_id", "GENERIC_01"),
            alert.get("rule_name", "Unknown Alert"),
            alert.get("severity", "MEDIUM").upper(),
            alert.get("category", "Anomaly"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("src_port"),
            alert.get("dst_port"),
            alert.get("protocol", "IP"),
            alert.get("description", ""),
            evidence_str,
            alert.get("acknowledged", 0)
        ))
        conn.commit()
        return cursor.lastrowid

    def insert_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        """Batch inserts multiple alerts."""
        if not alerts:
            return 0
        count = 0
        for alert in alerts:
            self.insert_alert(alert)
            count += 1
        return count

    def get_alerts(self, limit: int = 100, offset: int = 0, severity: Optional[str] = None,
                   acknowledged: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieves alerts filtered by severity or acknowledgement state."""
        conn = self._get_connection()
        cursor = conn.cursor()
        clauses = []
        params: List[Any] = []

        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            params.append(acknowledged)

        where_stmt = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
        SELECT * FROM alerts
        {where_stmt}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        cursor.execute(query, params)
        rows = cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["evidence_obj"] = json.loads(d.get("evidence") or "{}")
            except Exception:
                d["evidence_obj"] = d.get("evidence")
            result.append(d)
        return result

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a single alert with parsed evidence."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["evidence_obj"] = json.loads(d.get("evidence") or "{}")
        except Exception:
            d["evidence_obj"] = d.get("evidence")
        return d

    def acknowledge_alert(self, alert_id: int, ack_status: int = 1) -> bool:
        """Marks an alert as acknowledged or unacknowledged."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET acknowledged = ? WHERE id = ?", (ack_status, alert_id))
        conn.commit()
        return cursor.rowcount > 0

    # ------------------ Reconnaissance / Scans Operations ------------------

    def insert_scan(self, scan_data: Dict[str, Any]) -> int:
        """Inserts an Nmap reconnaissance scan record."""
        conn = self._get_connection()
        cursor = conn.cursor()
        query = """
        INSERT INTO scans (
            timestamp, target, scan_type, status, open_ports_count, results_json, raw_output
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        res_json = (
            json.dumps(scan_data.get("results", {}))
            if isinstance(scan_data.get("results"), (dict, list))
            else str(scan_data.get("results_json", "{}"))
        )
        cursor.execute(query, (
            scan_data.get("timestamp", time.time()),
            scan_data.get("target", "localhost"),
            scan_data.get("scan_type", "quick"),
            scan_data.get("status", "COMPLETED"),
            scan_data.get("open_ports_count", 0),
            res_json,
            scan_data.get("raw_output", "")
        ))
        conn.commit()
        return cursor.lastrowid

    def get_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves list of executed network scans."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["results"] = json.loads(d.get("results_json") or "{}")
            except Exception:
                d["results"] = {}
            result.append(d)
        return result

    # ------------------ Statistics & Metrics Aggregation ------------------

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Calculates aggregated metrics for the security monitoring dashboard."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Total counts
        cursor.execute("SELECT COUNT(*) FROM packets")
        total_packets = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM flows")
        total_flows = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
        critical_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM flows WHERE is_anomaly = 1")
        anomaly_flows = cursor.fetchone()[0]

        # Protocol distribution
        cursor.execute("""
        SELECT protocol, COUNT(*) as count
        FROM packets
        GROUP BY protocol
        ORDER BY count DESC
        LIMIT 10
        """)
        protocol_distribution = [dict(row) for row in cursor.fetchall()]

        # Top source IPs (Top talkers)
        cursor.execute("""
        SELECT src_ip, COUNT(*) as count, SUM(length) as total_bytes
        FROM packets
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 7
        """)
        top_src_ips = [dict(row) for row in cursor.fetchall()]

        # Top destination IPs
        cursor.execute("""
        SELECT dst_ip, COUNT(*) as count, SUM(length) as total_bytes
        FROM packets
        WHERE dst_ip IS NOT NULL AND dst_ip != ''
        GROUP BY dst_ip
        ORDER BY count DESC
        LIMIT 7
        """)
        top_dst_ips = [dict(row) for row in cursor.fetchall()]

        # Alert breakdown by severity
        cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
        """)
        alerts_by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

        # Alert breakdown by category
        cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM alerts
        GROUP BY category
        ORDER BY count DESC
        LIMIT 6
        """)
        alerts_by_category = [dict(row) for row in cursor.fetchall()]

        # Recent alerts (top 5)
        cursor.execute("""
        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5
        """)
        recent_alerts = [dict(row) for row in cursor.fetchall()]

        return {
            "total_packets": total_packets,
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "anomaly_flows": anomaly_flows,
            "protocol_distribution": protocol_distribution,
            "top_src_ips": top_src_ips,
            "top_dst_ips": top_dst_ips,
            "alerts_by_severity": alerts_by_severity,
            "alerts_by_category": alerts_by_category,
            "recent_alerts": recent_alerts,
        }

    def clear_database(self):
        """Clears all records for clean testing runs."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM packets;")
        cursor.execute("DELETE FROM flows;")
        cursor.execute("DELETE FROM alerts;")
        cursor.execute("DELETE FROM scans;")
        conn.commit()


# Default singleton instance
_default_db: Optional[DatabaseManager] = None


def get_db(db_path: Optional[str] = None) -> DatabaseManager:
    """Returns singleton DatabaseManager instance."""
    global _default_db
    if _default_db is None or db_path is not None:
        _default_db = DatabaseManager(db_path)
    return _default_db

"""
NetSentinel - Centralized Security Monitoring & Intrusion Detection Dashboard
Flask web application providing real-time network visualization, incident triage, and forensic analysis.
"""

import csv
import io
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
from werkzeug.utils import secure_filename

from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

# Add parent directory to sys.path so NetSentinel modules can be imported
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from analysis.flow_features import FlowAggregator
from capture.pcap_parser import PacketParser
from database.models import DatabaseManager, get_db
from detection.anomaly_detector import NetworkAnomalyDetector
from detection.rules import RuleEngine
from discovery.nmap_scanner import NmapScanner

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
    static_folder=os.path.join(BASE_DIR, "dashboard", "static")
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "netsentinel-dev-secret-key-change-in-production")
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "sample_pcaps")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB upload limit

db: DatabaseManager = get_db()
rule_engine = RuleEngine()
anomaly_detector = NetworkAnomalyDetector()
nmap_scanner = NmapScanner()


def ingest_pcap_file(filepath: str) -> Dict[str, Any]:
    """Parses a PCAP file, extracts bidirectional flows, runs rule engine, and performs ML anomaly scoring."""
    parser = PacketParser(filepath)
    packets = parser.parse_all()
    filename = os.path.basename(filepath)

    for pkt in packets:
        pkt["pcap_source"] = filename

    # 1. Store packets in DB
    db.insert_packets(packets)

    # 2. Extract Bidirectional Flows
    aggregator = FlowAggregator()
    aggregator.process_packets(packets)
    df_flows = aggregator.to_dataframe()

    # 3. Apply ML Anomaly Detection
    if not df_flows.empty:
        df_analyzed = anomaly_detector.predict_flows(df_flows)
        ml_alerts = anomaly_detector.generate_alerts_from_anomalies(df_analyzed)
        db.insert_alerts(ml_alerts)

        # Merge anomaly predictions back to flow dicts
        flow_dicts = []
        for _, row in df_analyzed.iterrows():
            f_dict = {
                "flow_key": row.get("flow_key", ""),
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "src_port": int(row.get("src_port", 0)),
                "dst_port": int(row.get("dst_port", 0)),
                "protocol": row.get("protocol", "IP"),
                "start_time": float(row.get("start_time", time.time())),
                "end_time": float(row.get("end_time", time.time())),
                "duration": float(row.get("duration", 0.0)),
                "total_packets": int(row.get("total_packets", 0)),
                "total_bytes": int(row.get("total_bytes", 0)),
                "fwd_packets": int(row.get("fwd_packets", 0)),
                "bwd_packets": int(row.get("bwd_packets", 0)),
                "syn_count": int(row.get("syn_count", 0)),
                "rst_count": int(row.get("rst_count", 0)),
                "flow_state": str(row.get("flow_state", "UNKNOWN")),
                "is_anomaly": bool(row.get("is_anomaly", False)),
                "anomaly_score": float(row.get("anomaly_score", 0.0)),
                "features": {col: row.get(col, 0.0) for col in anomaly_detector.FEATURE_COLUMNS}
            }
            flow_dicts.append(f_dict)
        db.insert_flows(flow_dicts)
    else:
        ml_alerts = []

    # 4. Apply Rule-based Intrusion Detection Engine
    rule_alerts = rule_engine.evaluate_packets(packets)
    db.insert_alerts(rule_alerts)

    total_alerts = len(rule_alerts) + len(ml_alerts)
    return {
        "status": "success",
        "filename": filename,
        "packets_count": len(packets),
        "flows_count": len(df_flows) if not df_flows.empty else 0,
        "rule_alerts_count": len(rule_alerts),
        "ml_alerts_count": len(ml_alerts),
        "total_alerts": total_alerts
    }


# =====================================================================
# Dashboard Views (HTML)
# =====================================================================

@app.route("/")
def dashboard_overview():
    """Main SOC monitoring dashboard view."""
    summary = db.get_dashboard_summary()
    return render_template("index.html", summary=summary)


@app.route("/packets")
def packets_view():
    """Packet inspection viewer."""
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    offset = (page - 1) * limit
    proto = request.args.get("protocol") or None
    ip_filter = request.args.get("ip") or None

    packets = db.get_packets(limit=limit, offset=offset, protocol=proto, ip_filter=ip_filter)
    return render_template(
        "packets.html",
        packets=packets,
        page=page,
        limit=limit,
        current_proto=proto or "",
        current_ip=ip_filter or ""
    )


@app.route("/flows")
def flows_view():
    """Flow session analysis and ML anomaly scores view."""
    anomaly_only = request.args.get("anomaly_only", "0") == "1"
    flows = db.get_flows(limit=100, anomaly_only=anomaly_only)
    return render_template("flows.html", flows=flows, anomaly_only=anomaly_only)


@app.route("/alerts")
def alerts_view():
    """Security alerts and incident triage view."""
    severity = request.args.get("severity") or None
    alerts = db.get_alerts(limit=100, severity=severity)
    return render_template("alerts.html", alerts=alerts, current_severity=severity or "ALL")


@app.route("/scans", methods=["GET", "POST"])
def scans_view():
    """Network reconnaissance and service exposure manager."""
    if request.method == "POST":
        target = request.form.get("target", "127.0.0.1").strip()
        scan_type = request.form.get("scan_type", "quick")
        ports = request.form.get("ports", "").strip() or None

        scan_result = nmap_scanner.scan(target, scan_type=scan_type, ports=ports)
        db.insert_scan(scan_result)
        flash(f"Scan completed for {target} ({scan_result.get('open_ports_count', 0)} open ports found).", "success")
        return redirect(url_for("scans_view"))

    scans = db.get_scans(limit=20)
    nmap_status = "Available (Nmap CLI)" if nmap_scanner.is_available else "Native Python Socket Engine (Fallback)"
    return render_template("scans.html", scans=scans, nmap_status=nmap_status)


@app.route("/investigate/<int:alert_id>")
def investigate_alert(alert_id: int):
    """Deep forensic drill-down from an alert to underlying packet and flow evidence."""
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        flash("Alert not found.", "danger")
        return redirect(url_for("alerts_view"))

    # Fetch contextual packets around the source IP
    related_packets = []
    if alert.get("src_ip"):
        related_packets = db.get_packets(limit=25, ip_filter=alert["src_ip"])

    return render_template("investigate.html", alert=alert, related_packets=related_packets)


@app.route("/upload", methods=["POST"])
def upload_pcap():
    """Handles PCAP file upload and executes automated analysis."""
    if "pcap_file" not in request.files:
        flash("No file part in upload request.", "danger")
        return redirect(url_for("dashboard_overview"))

    file = request.files["pcap_file"]
    if file.filename == "":
        flash("No selected file.", "warning")
        return redirect(url_for("dashboard_overview"))

    if file and (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)
        try:
            stats = ingest_pcap_file(save_path)
            flash(
                f"Successfully parsed {filename}: {stats['packets_count']} packets, "
                f"{stats['flows_count']} flows, {stats['total_alerts']} alerts flagged.",
                "success"
            )
        except Exception as e:
            flash(f"Error parsing PCAP: {e}", "danger")
    else:
        flash("Invalid file format. Please upload a .pcap or .pcapng file.", "danger")

    return redirect(url_for("dashboard_overview"))


@app.route("/api/replay-sample/<filename>", methods=["POST"])
def replay_sample_pcap(filename: str):
    """Replays an existing sample PCAP from sample_pcaps directory."""
    sample_path = os.path.join(BASE_DIR, "sample_pcaps", secure_filename(filename))
    if not os.path.exists(sample_path):
        return jsonify({"status": "error", "message": f"Sample file {filename} not found"}), 404
    try:
        stats = ingest_pcap_file(sample_path)
        flash(
            f"Ingested sample attack capture ({filename}): {stats['packets_count']} packets, "
            f"{stats['flows_count']} flows, {stats['total_alerts']} alerts flagged.",
            "success"
        )
        return jsonify(stats)
    except Exception as e:
        flash(f"Error replaying sample PCAP: {e}", "danger")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/report")
def security_report():
    """Generates an executive incident response and security monitoring summary report."""
    summary = db.get_dashboard_summary()
    alerts = db.get_alerts(limit=50)
    scans = db.get_scans(limit=5)
    return render_template("report.html", summary=summary, alerts=alerts, scans=scans, generated_at=time.ctime())


# =====================================================================
# REST API Endpoints (JSON & Exports)
# =====================================================================

@app.route("/api/summary")
def api_summary():
    """Returns dashboard summary data as JSON."""
    return jsonify(db.get_dashboard_summary())


@app.route("/api/packets")
def api_packets():
    """Returns paginated packet metadata."""
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    return jsonify(db.get_packets(limit=limit, offset=offset))


@app.route("/api/alerts")
def api_alerts():
    """Returns alerts list."""
    limit = int(request.args.get("limit", 100))
    severity = request.args.get("severity")
    return jsonify(db.get_alerts(limit=limit, severity=severity))


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
def api_ack_alert(alert_id: int):
    """Toggles acknowledgement status of an alert."""
    data = request.get_json() or {}
    status = data.get("acknowledged", 1)
    success = db.acknowledge_alert(alert_id, ack_status=status)
    return jsonify({"success": success, "alert_id": alert_id, "acknowledged": status})


@app.route("/api/clear", methods=["POST"])
def api_clear_data():
    """Clears all packet, flow, alert, and scan records from the database."""
    db.clear_database()
    flash("Database wiped successfully. Ready for clean test run.", "info")
    return redirect(url_for("dashboard_overview"))


@app.route("/api/export/alerts.csv")
def export_alerts_csv():
    """Exports all alerts into a downloadable CSV report."""
    alerts = db.get_alerts(limit=1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Alert ID", "Timestamp", "Rule ID", "Rule Name", "Severity",
        "Category", "Source IP", "Destination IP", "Protocol", "Description", "Acknowledged"
    ])
    for a in alerts:
        writer.writerow([
            a.get("id"),
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.get("timestamp", 0))),
            a.get("rule_id"),
            a.get("rule_name"),
            a.get("severity"),
            a.get("category"),
            a.get("src_ip"),
            a.get("dst_ip"),
            a.get("protocol"),
            a.get("description"),
            "Yes" if a.get("acknowledged") else "No"
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=netsentinel_alerts.csv"}
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

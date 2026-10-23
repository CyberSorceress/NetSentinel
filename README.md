# NetSentinel: Intelligent Network Security Monitoring and Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Packet_Dissection-Scapy_2.7-red.svg)](https://scapy.net/)
[![PyShark](https://img.shields.io/badge/Dissector-PyShark_0.6-orange.svg)](https://github.com/KimiNewt/pyshark)
[![Nmap](https://img.shields.io/badge/Recon-Nmap_7.95-green.svg)](https://nmap.org/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Isolation_Forest-yellow.svg)](https://scikit-learn.org/)
[![Flask](https://img.shields.io/badge/Dashboard-Flask_3.1-black.svg)](https://flask.palletsprojects.com/)

**Domain:** Computer Networks | Network Security | Intrusion Detection (IDS/NIDS) | Network Forensics  
**Portfolio Reference:** [NetSentinel Project Reference](https://aman9673.github.io/?utm_source=chatgpt.com)

---

## Technical Summary

NetSentinel is a full-featured Network Security Monitoring (NSM) and Intrusion Detection System (IDS) developed in Python. The system implements passive packet acquisition, protocol dissection across layers 2 through 7, bidirectional session reconstruction, heuristic rule evaluation, and unsupervised anomaly detection using Scikit-Learn's Isolation Forest algorithm.

### Key Capabilities
* **Deep Packet Inspection:** Extracts layer-specific metadata including Ethernet MAC addressing, ARP operations, IPv4/IPv6 headers (TTL, TOS, fragmentation), TCP control flags, UDP lengths, ICMP types, DNS queries, and TLS Server Name Indication (SNI) from unencrypted handshakes.
* **Network Reconnaissance and Exposure Auditing:** Integrates an Nmap execution engine (with a native Python multi-threaded socket fallback) to map active hosts, discover open ports, identify running services, and compute quantitative exposure risk ratings.
* **Dual Detection Architecture:** Combines a deterministic rule engine for known attack patterns (e.g., port scans, TCP SYN floods, stealth NULL/XMAS scans, DNS exfiltration, cleartext credentials) with statistical anomaly detection using unsupervised machine learning.
* **Session Reconstruction:** Implements a canonical 5-tuple flow aggregator that correlates forward and backward packet streams into coherent conversations, tracking TCP finite state machine transitions and computing statistical metrics.
* **Centralized SOC Monitoring:** Provides an interactive Flask-based Security Operations Center dashboard featuring real-time telemetry charts, a Wireshark-style packet inspector with raw hexadecimal dumps, alert triage workflows, and incident reporting.

---

## System Architecture

```text
+----------------------------------------------------------------------------------------------------+
|                                    1. TRAFFIC INGESTION LAYER                                      |
|                                                                                                    |
|   +------------------------------------+             +-----------------------------------------+   |
|   |  Live Network Interface Capture    |             |  Offline Packet Capture (.pcap/.pcapng) |   |
|   |  (Scapy AsyncSniffer + BPF Filter) |             |  (Wireshark / tcpdump traces)           |   |
|   +-----------------+------------------+             +--------------------+--------------------+   |
+---------------------|-----------------------------------------------------|------------------------+
                      |                                                     |
                      +--------------------------+--------------------------+
                                                 |
                                                 v
+----------------------------------------------------------------------------------------------------+
|                                  2. PACKET PARSING & DISSECTION                                    |
|                                                                                                    |
|   +--------------------------------------------------------------------------------------------+   |
|   |  Scapy & PyShark Deep Packet Dissector (Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS)     |   |
|   |  - Header Extraction: IP TTL, TOS, Fragment Flags, TCP Flags (SYN/ACK/FIN/RST/PSH/URG)    |   |
|   |  - Application Metadata: HTTP Methods/Headers, DNS Queries/Entropy, TLS SNI (ClientHello) |   |
|   +--------------------------------------------+-----------------------------------------------+   |
+------------------------------------------------|---------------------------------------------------+
                                                 |
         +---------------------------------------+---------------------------------------+
         |                                                                               |
         v                                                                               v
+------------------------------------+                         +-------------------------------------+
|    3A. RULE-BASED IDS ENGINE       |                         |  3B. BIDIRECTIONAL FLOW AGGREGATOR  |
|                                    |                         |                                     |
|  Heuristic & Signature Detections: |                         |  Canonical 5-Tuple Session Grouping |
|  - Horizontal/Vertical Port Scans  |                         |  (src_ip, dst_ip, sport, dport, pr) |
|  - Stealth Scans (NULL, XMAS, FIN) |                         |  State Machine (SYN_SENT, EST, RST) |
|  - TCP SYN Flood (T1498)           |                         +------------------+------------------+
|  - ICMP Echo Flood Spike           |                                            |
|  - DNS Tunneling / High Entropy    |                                            v
|  - Cleartext HTTP/FTP Auth Leak    |                         +-------------------------------------+
|  - ARP Cache Poisoning (T1557)     |                         |      FLOW FEATURE ENGINEERING       |
+-----------------+------------------+                         |                                     |
                  |                                            |  Pandas Statistical Feature Matrix: |
                  |                                            |  - Packet & Byte Rates (PPS / BPS)  |
                  |                                            |  - Inter-Arrival Times (Mean/Std)   |
                  |                                            |  - TCP Flag Ratios (SYN/RST/ACK)    |
                  |                                            |  - Unique Destination Port Counts   |
                  |                                            +------------------+------------------+
                  |                                                               |
                  |                                                               v
                  |                                            +-------------------------------------+
                  |                                            |   UNSUPERVISED ML ANOMALY ENGINE    |
                  |                                            |                                     |
                  |                                            |  Scikit-Learn Isolation Forest:     |
                  |                                            |  - Multidimensional Outlier Scoring |
                  |                                            |  - Baseline Profiling & Z-Score Exp |
                  +----------------------+---------------------+------------------+------------------+
                                         |
                                         v
+----------------------------------------------------------------------------------------------------+
|                                    4. PERSISTENCE & AUDIT LAYER                                    |
|                                                                                                    |
|   +--------------------------------------------------------------------------------------------+   |
|   |  SQLite Database (WAL Mode, Thread-Safe)                                                   |   |
|   |  Tables: packets | flows | alerts | scans | audit_logs                                     |   |
|   +--------------------------------------------+-----------------------------------------------+   |
+------------------------------------------------|---------------------------------------------------+
                                                 |
         +---------------------------------------+---------------------------------------+
         |                                                                               |
         v                                                                               v
+------------------------------------+                         +-------------------------------------+
|     5A. FLASK SOC MONITORING UI    |                         |  5B. INCIDENT RESPONSE & FORENSICS  |
|                                    |                         |                                     |
|  - Real-Time Protocol Breakdown    |                         |  - Deep Alert Drill-Down to Frame   |
|  - Top Talkers & Traffic Timelines |                         |  - Raw Hex & ASCII Payload Viewer   |
|  - Alert Severity Triage (CRIT/HI) |                         |  - MITRE ATT&CK Technique Mapping   |
|  - Recon Hub (Nmap XML / Sockets)  |                         |  - Automated CSV & PDF Export       |
+------------------------------------+                         +-------------------------------------+
```

---

## MITRE ATT&CK Technique Mapping

NetSentinel correlates network indicators with standard enterprise ATT&CK techniques:

| Technique ID | Technique Name | Detection Mechanism | Severity |
| :--- | :--- | :--- | :--- |
| **T1046** | Network Service Discovery | `NET-SCAN-001` (Horizontal Port Scan)<br>`NET-SCAN-003` (Stealth NULL / XMAS Scan) | **HIGH** |
| **T1498** | Network Denial of Service | `NET-DOS-001` (TCP SYN Flood)<br>`NET-DOS-002` (ICMP Echo Flood) | **CRITICAL** / **MEDIUM** |
| **T1071.004** | DNS Application Layer Protocol | `NET-EXFIL-001` (High-Entropy Subdomain Query) | **CRITICAL** |
| **T1048** | Exfiltration Over Alternative Protocol | `NET-EXFIL-001` (Base64/Hex Encoded Tunneling) | **CRITICAL** |
| **T1552** | Unsecured Credentials | `NET-DATA-001` (HTTP Basic Auth Transmission)<br>`NET-DATA-002` (Cleartext FTP Credentials) | **HIGH** / **MEDIUM** |
| **T1110** | Brute Force Authentication | `NET-AUTH-001` (Rapid Connection Failures on Ports 22/3389) | **HIGH** |
| **T1557.002** | ARP Spoofing / Poisoning | `NET-MITM-001` (Conflicting MAC Bindings for Single IP) | **CRITICAL** |
| **Behavioral** | Statistical Outlier Anomaly | `ML-ANOMALY-001` (Isolation Forest Multi-Feature Deviation) | **HIGH** |

---

## Repository Structure

```text
NetSentinel/
├── capture/
│   ├── __init__.py
│   ├── live_capture.py       # Asynchronous live packet sniffer with BPF support
│   └── pcap_parser.py        # Offline PCAP/PCAPNG parser with deep protocol inspection
├── discovery/
│   ├── __init__.py
│   └── nmap_scanner.py       # Nmap CLI driver with XML parser and socket fallback
├── detection/
│   ├── __init__.py
│   ├── rules.py              # Heuristic and signature-based IDS rule engine
│   └── anomaly_detector.py   # Scikit-learn Isolation Forest model and feature scaler
├── analysis/
│   ├── __init__.py
│   └── flow_features.py      # Bidirectional 5-tuple flow aggregator and feature extractor
├── dashboard/
│   ├── __init__.py
│   ├── app.py                # Centralized Flask web dashboard and REST APIs
│   ├── templates/            # HTML5 dashboard templates
│   │   ├── base.html         # Base layout with navigation and upload modal
│   │   ├── index.html        # SOC overview with telemetry graphs
│   │   ├── packets.html      # Deep packet inspector with hexadecimal viewer
│   │   ├── flows.html        # Flow session table and ML anomaly scores
│   │   ├── alerts.html       # Security alert management and triage
│   │   ├── scans.html        # Reconnaissance hub and port exposure audit
│   │   ├── investigate.html  # Forensic incident drill-down view
│   │   └── report.html       # Printable executive security report
│   └── static/               # Styling and scripts
├── database/
│   ├── __init__.py
│   └── models.py             # SQLite persistence layer with WAL mode
├── sample_pcaps/
│   ├── generate_pcaps.py     # Synthetic generator for benign and attack PCAPs
│   ├── normal_web_traffic.pcap
│   ├── syn_port_scan.pcap
│   ├── syn_flood_dos.pcap
│   ├── dns_tunneling.pcap
│   └── cleartext_credentials.pcap
├── tests/
│   ├── __init__.py
│   └── test_netsentinel.py   # Test suite for database, parsing, rules, and ML
├── netsentinel.py            # Master command-line interface (CLI)
├── requirements.txt          # Python dependencies
└── README.md                 # Technical project documentation
```

---

## Installation & Setup

### Prerequisites
* Python 3.10 or higher
* Nmap (Optional; included native socket scanner functions independently)
* Wireshark / TShark (Optional; Scapy parser operates natively without external binaries)

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/aman9673/NetSentinel.git
cd NetSentinel

# Create and activate a virtual environment
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### Dependency Manifest (`requirements.txt`)

```text
scapy>=2.5.0
pyshark>=0.6.0
flask>=3.0.0
pandas>=2.0.0
scikit-learn>=1.4.0
scipy>=1.12.0
numpy>=1.26.0
rich>=13.7.0
reportlab>=4.0.0
joblib>=1.3.0
```

---

## Command-Line Interface (CLI)

The primary entry point is `netsentinel.py`, providing subcommands for ingestion, analysis, scanning, and web serving.

### 1. Generating Test Datasets
Generates synthetic network traces covering benign operations and simulated cyber attacks:

```bash
python netsentinel.py generate-samples
```

Output:
```text
[*] Generating sample PCAPs into sample_pcaps...
[+] Successfully created datasets:
    - normal_traffic      : normal_web_traffic.pcap (1814 bytes)
    - port_scan           : syn_port_scan.pcap (2204 bytes)
    - syn_flood           : syn_flood_dos.pcap (2560 bytes)
    - dns_tunneling       : dns_tunneling.pcap (626 bytes)
    - cleartext_creds     : cleartext_credentials.pcap (450 bytes)
```

### 2. Deep Packet Inspection
Inspects packet headers, protocol hierarchies, and flags from an offline capture:

```bash
python netsentinel.py parse sample_pcaps/normal_web_traffic.pcap --max-packets 10
```

### 3. Executing Intrusion Detection
Runs rule evaluations and machine learning inference against a capture file:

```bash
python netsentinel.py detect sample_pcaps/syn_port_scan.pcap
python netsentinel.py detect sample_pcaps/dns_tunneling.pcap
```

Output excerpt:
```text
[+] Analysis Complete: 36 packets, 18 sessions, 3 alerts found.

Detected Security Incidents:
+----------+--------------+------------------------------------+----------------+--------------+-----------------+
| Severity | Rule ID      | Threat Name                        | Category       | Attacker     | Target          |
+----------+--------------+------------------------------------+----------------+--------------+-----------------+
| HIGH     | NET-SCAN-003 | Stealth TCP NULL Scan Detected     | Reconnaissance | 10.20.30.40  | 192.168.1.10:80 |
| HIGH     | NET-SCAN-003 | Stealth TCP XMAS Scan Detected     | Reconnaissance | 10.20.30.40  | 192.168.1.10:80 |
| HIGH     | NET-SCAN-001 | Horizontal Port Scan Activity      | Reconnaissance | 10.20.30.40  | Multiple:*      |
+----------+--------------+------------------------------------+----------------+--------------+-----------------+
```

### 4. Running Network Reconnaissance
Performs an authorized scan against an IP address or subnet:

```bash
# Fast top-ports scan
python netsentinel.py scan 127.0.0.1 --type quick

# Service and version discovery on specific ports
python netsentinel.py scan 127.0.0.1 --type service --ports 21,22,80,443,3389
```

### 5. Training the Isolation Forest Model
Trains the machine learning anomaly detector on baseline normal network flows:

```bash
python netsentinel.py train-ml sample_pcaps/normal_web_traffic.pcap
```

### 6. Starting the Centralized Dashboard
Launches the Flask web server:

```bash
python netsentinel.py dashboard --port 5000
```
Access the dashboard via web browser at `http://127.0.0.1:5000`.

---

## Python API Usage

Components can be integrated programmatically into automated pipelines or custom scripts:

### Parsing Packets Programmatically
```python
from capture.pcap_parser import PacketParser

parser = PacketParser("sample_pcaps/normal_web_traffic.pcap")
packets = parser.parse_all()

for pkt in packets[:5]:
    print(f"Frame #{pkt['frame_num']} | {pkt['protocol']} | {pkt['src_ip']} -> {pkt['dst_ip']} | Flags: {pkt['flags']}")
```

### Flow Feature Extraction and Machine Learning Scoring
```python
import pandas as pd
from capture.pcap_parser import PacketParser
from analysis.flow_features import FlowAggregator
from detection.anomaly_detector import NetworkAnomalyDetector

# 1. Parse packets
packets = PacketParser("sample_pcaps/syn_flood_dos.pcap").parse_all()

# 2. Aggregate bidirectional sessions
aggregator = FlowAggregator()
aggregator.process_packets(packets)
df_flows = aggregator.to_dataframe()

# 3. Detect anomalies using Isolation Forest
detector = NetworkAnomalyDetector()
df_scored = detector.predict_flows(df_flows)

anomalies = df_scored[df_scored["is_anomaly"] == True]
print(f"Identified {len(anomalies)} anomalous sessions:")
print(anomalies[["flow_key", "anomaly_score", "top_deviant_features"]])
```

### Rule-Based Threat Evaluation
```python
from capture.pcap_parser import PacketParser
from detection.rules import RuleEngine

packets = PacketParser("sample_pcaps/dns_tunneling.pcap").parse_all()
engine = RuleEngine()
alerts = engine.evaluate_packets(packets)

for alert in alerts:
    print(f"[{alert['severity']}] {alert['rule_name']} - {alert['description']}")
```

---

## Security Operations Center (SOC) Dashboard

The dashboard provides a unified graphical interface:

* **SOC Overview (`/`):** Summary metrics (total packets, sessions, alerts, critical incidents), protocol breakdown doughnut chart, source IP traffic volume bar chart, and recent alert feed.
* **Packet Inspector (`/packets`):** Filterable, paginated table of individual packet frames with protocol filtering and modal hexadecimal/ASCII dissection.
* **Flow & ML Analysis (`/flows`):** Bidirectional session view displaying duration, byte/packet throughput, TCP state machine classifications, and Isolation Forest anomaly score meters.
* **Alert Management (`/alerts`):** Triage center with filtering by severity (CRITICAL, HIGH, MEDIUM, LOW) and acknowledgement state management.
* **Reconnaissance Hub (`/scans`):** Form-driven network discovery interface with automated exposure risk classification.
* **Incident Investigation (`/investigate/<id>`):** Detailed view correlating an alert with MITRE ATT&CK techniques, forensic evidence payloads, and related network packets.
* **Executive Report (`/report`):** Formal security audit summary designed for browser printing or export to PDF.

---

## Verification and Testing

Execute the comprehensive automated test suite to validate all system modules:

```bash
python -m unittest tests/test_netsentinel.py -v
```

### Test Scope
* **Database Operations:** Verifies schema generation, indexed queries, concurrent WAL writes, and alert acknowledgements.
* **Packet Dissection:** Confirms header extraction across Ethernet, ARP, IPv4, TCP, UDP, ICMP, and DNS protocols.
* **Flow Construction:** Tests bidirectional session grouping, TCP handshake completion tracking (`ESTABLISHED`), and feature calculation.
* **Detection Engine:** Validates triggering thresholds for horizontal port scans, stealth scans (NULL/XMAS), SYN floods, DNS tunneling, and cleartext credential transmission.
* **Machine Learning Pipeline:** Tests Isolation Forest model fitting, serialization round-trips, and statistical outlier classification.
* **Flask Endpoints:** Validates HTTP responses for core web routes, REST APIs, and CSV report downloads.

---

## Ethical Use and Authorization Notice

NetSentinel is intended exclusively for defensive network security monitoring, authorized penetration testing, vulnerability assessment in controlled lab environments, and educational cybersecurity research. 

Unauthorized monitoring, packet capture, or scanning against network systems without prior explicit written consent from the resource owner is strictly prohibited and may violate local, national, and international cybersecurity laws.

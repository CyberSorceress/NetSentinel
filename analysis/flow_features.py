"""
NetSentinel - Traffic Analysis & Flow Feature Extraction
Bidirectional session tracking, TCP state reconstruction, and statistical feature engineering for ML models.
"""

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd


class FlowSession:
    """Represents a single bidirectional network conversation between two endpoints."""

    def __init__(self, flow_key: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.flow_key = flow_key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper()

        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.packet_timestamps: List[float] = []
        self.packet_lengths: List[int] = []

        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.urg_count = 0

        self.has_syn = False
        self.has_syn_ack = False
        self.has_handshake_ack = False
        self.is_closed = False
        self.is_reset = False

    def add_packet(self, pkt: Dict[str, Any]):
        """Ingests a packet into this bidirectional flow and updates state metrics."""
        ts = pkt.get("timestamp", 0.0)
        length = pkt.get("length", 0)
        pkt_src_ip = pkt.get("src_ip")
        flags = str(pkt.get("flags", "")).upper()

        if not self.packet_timestamps:
            self.start_time = ts
        self.end_time = ts
        self.packet_timestamps.append(ts)
        self.packet_lengths.append(length)

        # Determine direction
        is_forward = (pkt_src_ip == self.src_ip)
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length

        # TCP Flag analysis
        if "S" in flags:
            self.syn_count += 1
            if "A" in flags:
                self.has_syn_ack = True
            else:
                self.has_syn = True
        if "A" in flags:
            self.ack_count += 1
            if self.has_syn and self.has_syn_ack and not self.has_handshake_ack:
                if is_forward:
                    self.has_handshake_ack = True
        if "F" in flags:
            self.fin_count += 1
            self.is_closed = True
        if "R" in flags:
            self.rst_count += 1
            self.is_reset = True
        if "P" in flags:
            self.psh_count += 1
        if "U" in flags:
            self.urg_count += 1

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def flow_state(self) -> str:
        """Determines the TCP session state based on observed flags."""
        if self.protocol != "TCP":
            return "NON_TCP"
        if self.is_reset:
            return "RESET"
        if self.is_closed:
            return "CLOSED"
        if self.has_handshake_ack or (self.has_syn and self.has_syn_ack):
            return "ESTABLISHED"
        if self.has_syn and not self.has_syn_ack:
            return "HALF_OPEN"
        return "IN_PROGRESS"

    def compute_features(self, host_dst_ports_count: int = 1) -> Dict[str, Any]:
        """Calculates statistical metrics and engineered features for intrusion detection."""
        dur = self.duration
        pkts = self.total_packets
        bytes_total = self.total_bytes

        # Rates (avoid division by zero with minimum 1ms duration)
        effective_dur = max(dur, 0.001)
        pkt_rate = pkts / effective_dur
        byte_rate = bytes_total / effective_dur

        # Packet length statistics
        avg_pkt_size = bytes_total / pkts if pkts > 0 else 0.0
        std_pkt_size = float(np.std(self.packet_lengths)) if len(self.packet_lengths) > 1 else 0.0

        # TCP Flag ratios
        syn_ratio = self.syn_count / pkts if pkts > 0 else 0.0
        rst_ratio = self.rst_count / pkts if pkts > 0 else 0.0
        ack_ratio = self.ack_count / pkts if pkts > 0 else 0.0

        # Inter-Arrival Times (IAT)
        iat_mean = 0.0
        iat_std = 0.0
        iat_max = 0.0
        if len(self.packet_timestamps) > 1:
            iats = np.diff(self.packet_timestamps)
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
            iat_max = float(np.max(iats))

        return {
            "duration": round(dur, 4),
            "total_packets": pkts,
            "total_bytes": bytes_total,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "packet_rate": round(pkt_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "std_packet_size": round(std_pkt_size, 2),
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "rst_count": self.rst_count,
            "fin_count": self.fin_count,
            "syn_ratio": round(syn_ratio, 4),
            "rst_ratio": round(rst_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "iat_mean": round(iat_mean, 6),
            "iat_std": round(iat_std, 6),
            "iat_max": round(iat_max, 6),
            "unique_dst_ports": host_dst_ports_count,
            "flow_state": self.flow_state,
        }

    def to_dict(self, host_dst_ports_count: int = 1) -> Dict[str, Any]:
        """Serializes the flow to a dictionary ready for DB storage and JSON APIs."""
        features = self.compute_features(host_dst_ports_count)
        return {
            "flow_key": self.flow_key,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "syn_count": self.syn_count,
            "rst_count": self.rst_count,
            "flow_state": self.flow_state,
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "features": features
        }


class FlowAggregator:
    """Aggregates an ordered sequence of raw packets into bidirectional network flows."""

    FEATURE_COLUMNS = [
        "duration",
        "total_packets",
        "total_bytes",
        "packet_rate",
        "byte_rate",
        "avg_packet_size",
        "syn_ratio",
        "rst_ratio",
        "ack_ratio",
        "iat_mean",
        "iat_std",
        "unique_dst_ports",
    ]

    def __init__(self):
        self.flows: Dict[str, FlowSession] = {}
        # Track host port diversity for port scan feature calculation
        self.host_probed_ports: Dict[str, Set[int]] = defaultdict(set)

    @staticmethod
    def get_canonical_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> Tuple[str, bool]:
        """
        Creates a consistent bidirectional key.
        Returns (flow_key, is_original_order).
        """
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 <= ep2:
            key = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}/{protocol}"
            return key, True
        else:
            key = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}/{protocol}"
            return key, False

    def process_packet(self, pkt: Dict[str, Any]):
        """Ingests a packet dict and attaches it to its corresponding flow."""
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            return

        src_port = pkt.get("src_port") or 0
        dst_port = pkt.get("dst_port") or 0
        protocol = pkt.get("protocol") or "OTHER"

        if dst_port > 0:
            self.host_probed_ports[src_ip].add(dst_port)

        flow_key, is_orig = self.get_canonical_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if flow_key not in self.flows:
            # First packet seen for this session
            self.flows[flow_key] = FlowSession(
                flow_key=flow_key,
                src_ip=src_ip if is_orig else dst_ip,
                dst_ip=dst_ip if is_orig else src_ip,
                src_port=src_port if is_orig else dst_port,
                dst_port=dst_port if is_orig else src_port,
                protocol=protocol
            )

        self.flows[flow_key].add_packet(pkt)

    def process_packets(self, packets: List[Dict[str, Any]]):
        """Processes a list of packet dicts."""
        for pkt in packets:
            self.process_packet(pkt)

    def get_flow_dicts(self) -> List[Dict[str, Any]]:
        """Returns list of flow dictionaries with complete feature metrics."""
        flow_list = []
        for flow in self.flows.values():
            probed_count = len(self.host_probed_ports.get(flow.src_ip, set()))
            flow_list.append(flow.to_dict(host_dst_ports_count=probed_count))
        return flow_list

    def to_dataframe(self) -> pd.DataFrame:
        """Transforms flows into a Pandas DataFrame for statistical and ML analysis."""
        rows = []
        for flow in self.flows.values():
            probed_count = len(self.host_probed_ports.get(flow.src_ip, set()))
            feat = flow.compute_features(host_dst_ports_count=probed_count)
            feat["flow_key"] = flow.flow_key
            feat["src_ip"] = flow.src_ip
            feat["dst_ip"] = flow.dst_ip
            feat["src_port"] = flow.src_port
            feat["dst_port"] = flow.dst_port
            feat["protocol"] = flow.protocol
            rows.append(feat)

        if not rows:
            return pd.DataFrame(columns=["flow_key", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"] + self.FEATURE_COLUMNS)
        return pd.DataFrame(rows)

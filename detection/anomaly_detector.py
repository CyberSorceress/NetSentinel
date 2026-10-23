"""
NetSentinel - Machine Learning Network Anomaly Detection
Unsupervised anomaly detection using Scikit-learn's Isolation Forest over statistical network flow features.
"""

import os
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class NetworkAnomalyDetector:
    """
    Trains and applies an Isolation Forest model to detect unusual network sessions
    and statistical behavioral anomalies without requiring predefined rule signatures.
    """

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

    def __init__(self, contamination: float = 0.05, random_state: int = 42, model_path: Optional[str] = None):
        self.contamination = contamination
        self.random_state = random_state
        if model_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_path = os.path.join(base_dir, "detection", "isolation_forest.joblib")
        self.model_path = model_path

        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_means: Dict[str, float] = {}
        self.feature_stds: Dict[str, float] = {}

        # Auto-load existing model if present
        if os.path.exists(self.model_path):
            self.load_model()

    def _prepare_matrix(self, df: pd.DataFrame) -> np.ndarray:
        """Extracts and sanitizes numerical feature columns from DataFrame."""
        for col in self.FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0.0

        sub_df = df[self.FEATURE_COLUMNS].copy()
        # Clean infinite and NaN values
        sub_df = sub_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return sub_df.values

    def fit(self, df_flows: pd.DataFrame) -> Dict[str, Any]:
        """
        Fits the Isolation Forest on a baseline dataset of normal/typical network flows.
        Computes baseline feature distributions for explainability.
        """
        if len(df_flows) < 5:
            # Need at least a small sample of flows
            raise ValueError(f"Insufficient flows for training (got {len(df_flows)}, minimum 5 required).")

        X = self._prepare_matrix(df_flows)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True

        # Store baseline distribution statistics
        for i, col in enumerate(self.FEATURE_COLUMNS):
            vals = X[:, i]
            self.feature_means[col] = float(np.mean(vals))
            self.feature_stds[col] = float(np.std(vals)) if np.std(vals) > 0 else 1.0

        self.save_model()

        return {
            "status": "trained",
            "samples": len(df_flows),
            "features_used": self.FEATURE_COLUMNS,
            "contamination_rate": self.contamination,
        }

    def predict_flows(self, df_flows: pd.DataFrame) -> pd.DataFrame:
        """
        Infers anomaly status and anomaly scores for each flow in df_flows.
        Returns a DataFrame with columns: ['is_anomaly', 'anomaly_score', 'anomaly_severity', 'top_deviant_features'].
        """
        if df_flows.empty:
            return df_flows

        if not self.is_trained:
            # If not yet trained, fit on current batch as self-supervised baseline
            if len(df_flows) >= 5:
                self.fit(df_flows)
            else:
                df_copy = df_flows.copy()
                df_copy["is_anomaly"] = False
                df_copy["anomaly_score"] = 0.0
                df_copy["anomaly_severity"] = "NORMAL"
                df_copy["top_deviant_features"] = ""
                return df_copy

        X = self._prepare_matrix(df_flows)
        X_scaled = self.scaler.transform(X)

        # IsolationForest decision_function: lower score = more anomalous. Negative is anomaly.
        raw_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)  # -1 for anomaly, 1 for normal

        df_result = df_flows.copy()
        # Normalize anomaly score: 0.0 (normal) to 1.0 (highly anomalous)
        # Raw scores typically span from ~ -0.4 (extreme anomaly) to +0.3 (very normal)
        normalized_scores = []
        is_anom_list = []
        severities = []
        deviations = []

        for i, (pred, raw_sc) in enumerate(zip(predictions, raw_scores)):
            is_anom = (pred == -1)
            # Normalize to [0, 1] range: lower raw_sc -> higher normalized score
            norm_sc = float(np.clip((0.2 - raw_sc) / 0.5, 0.0, 1.0))

            if is_anom:
                if norm_sc >= 0.8:
                    severity = "CRITICAL"
                elif norm_sc >= 0.6:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
            else:
                severity = "NORMAL"

            # Explain top deviant features (Z-score deviation from baseline)
            deviant_feats = []
            if is_anom:
                for j, col in enumerate(self.FEATURE_COLUMNS):
                    val = X[i, j]
                    mean = self.feature_means.get(col, 0.0)
                    std = self.feature_stds.get(col, 1.0)
                    z_score = abs(val - mean) / (std if std > 0 else 1.0)
                    if z_score > 2.0:
                        deviant_feats.append(f"{col}(z={z_score:.1f}, val={val:.1f})")

            is_anom_list.append(is_anom)
            normalized_scores.append(round(norm_sc, 3))
            severities.append(severity)
            deviations.append("; ".join(deviant_feats[:3]))

        df_result["is_anomaly"] = is_anom_list
        df_result["anomaly_score"] = normalized_scores
        df_result["anomaly_severity"] = severities
        df_result["top_deviant_features"] = deviations
        return df_result

    def generate_alerts_from_anomalies(self, df_analyzed_flows: pd.DataFrame) -> List[Dict[str, Any]]:
        """Converts detected ML anomalies into standardized NetSentinel security alerts."""
        alerts = []
        anomalies = df_analyzed_flows[df_analyzed_flows["is_anomaly"] == True]

        for _, row in anomalies.iterrows():
            flow_key = row.get("flow_key", "")
            src_ip = row.get("src_ip", "")
            dst_ip = row.get("dst_ip", "")
            src_port = int(row.get("src_port", 0))
            dst_port = int(row.get("dst_port", 0))
            protocol = row.get("protocol", "IP")
            severity = row.get("anomaly_severity", "HIGH")
            score = row.get("anomaly_score", 0.0)
            dev_feats = row.get("top_deviant_features", "Statistical Outlier")

            alerts.append({
                "timestamp": time.time(),
                "rule_id": "ML-ANOMALY-001",
                "rule_name": "Isolation Forest Flow Anomaly",
                "severity": severity,
                "category": "Behavioral Anomaly",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "description": f"Unsupervised model flagged abnormal session {flow_key} (Anomaly score: {score:.2f}). Deviations: {dev_feats}",
                "evidence": {
                    "flow_key": flow_key,
                    "anomaly_score": score,
                    "model": "IsolationForest",
                    "deviant_features": dev_feats,
                    "total_packets": int(row.get("total_packets", 0)),
                    "total_bytes": int(row.get("total_bytes", 0)),
                    "packet_rate": float(row.get("packet_rate", 0.0)),
                    "syn_ratio": float(row.get("syn_ratio", 0.0)),
                }
            })

        return alerts

    def save_model(self, path: Optional[str] = None):
        """Persists trained model and scaler to disk."""
        target_path = path or self.model_path
        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        bundle = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "is_trained": self.is_trained,
            "contamination": self.contamination,
        }
        joblib.dump(bundle, target_path)

    def load_model(self, path: Optional[str] = None):
        """Loads serialized model from disk."""
        target_path = path or self.model_path
        if not os.path.exists(target_path):
            return False
        try:
            bundle = joblib.load(target_path)
            self.model = bundle["model"]
            self.scaler = bundle["scaler"]
            self.feature_means = bundle.get("feature_means", {})
            self.feature_stds = bundle.get("feature_stds", {})
            self.is_trained = bundle.get("is_trained", True)
            self.contamination = bundle.get("contamination", 0.05)
            return True
        except Exception:
            return False

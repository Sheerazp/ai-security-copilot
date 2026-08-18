"""
ml_service.py
--------------
Loads the trained models once at startup and exposes a simple `score_event()`
function that the API endpoints and the copilot's tools both call.
"""

from pathlib import Path
from typing import Dict, Any

import joblib
import numpy as np
import pandas as pd

MODEL_DIR = Path(__file__).parent.parent.parent / "models"

FEATURES_ORDER = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    "num_failed_logins", "logged_in", "wrong_fragment", "urgent", "hot",
    "protocol_type_enc",
]

SEVERITY_MAP = {
    "BENIGN": "normal",
    "PortScan": "suspicious",
    "BruteForce": "suspicious",
    "Botnet": "critical",
    "DDoS": "critical",
}


class MLService:
    def __init__(self):
        self.intrusion_model = joblib.load(MODEL_DIR / "intrusion_model.pkl")
        self.label_encoder = joblib.load(MODEL_DIR / "label_encoder.pkl")
        self.proto_encoder = joblib.load(MODEL_DIR / "proto_encoder.pkl")

        self.anomaly_model = joblib.load(MODEL_DIR / "anomaly_model.pkl")
        self.anomaly_scaler = joblib.load(MODEL_DIR / "anomaly_scaler.pkl")

    def _encode_protocol(self, protocol_type: str) -> int:
        try:
            return int(self.proto_encoder.transform([protocol_type])[0])
        except ValueError:
            # unseen protocol at inference time -> fall back to most common (tcp)
            return int(self.proto_encoder.transform(["tcp"])[0])

    def score_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        event: dict with the raw feature columns (see FEATURES_ORDER, minus
        the encoded protocol -- pass 'protocol_type' as a string like 'tcp').
        Returns predicted label, severity, confidence, and anomaly info.
        """
        proto_enc = self._encode_protocol(event.get("protocol_type", "tcp"))
        row = {**event, "protocol_type_enc": proto_enc}
        X = pd.DataFrame([[row[c] for c in FEATURES_ORDER]], columns=FEATURES_ORDER)

        # Intrusion classifier
        pred_idx = self.intrusion_model.predict(X)[0]
        proba = self.intrusion_model.predict_proba(X)[0]
        label = self.label_encoder.inverse_transform([pred_idx])[0]
        confidence = float(np.max(proba))
        severity = SEVERITY_MAP.get(label, "normal")

        # Anomaly detector (unsupervised, uses the non-encoded feature set)
        anomaly_features = [
            "duration", "src_bytes", "dst_bytes", "count", "srv_count",
            "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
            "num_failed_logins", "logged_in", "wrong_fragment", "urgent", "hot",
        ]
        X_anom = pd.DataFrame([[event[c] for c in anomaly_features]], columns=anomaly_features)
        X_anom_scaled = self.anomaly_scaler.transform(X_anom)
        raw_score = self.anomaly_model.decision_function(X_anom_scaled)[0]
        is_anomaly = bool(self.anomaly_model.predict(X_anom_scaled)[0] == -1)
        # normalize roughly into 0-1 (higher = more anomalous)
        anomaly_score = float(np.clip(0.5 - raw_score, 0, 1))

        return {
            "predicted_label": label,
            "severity": severity,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
        }


# Singleton instance loaded once at API startup
ml_service = MLService()

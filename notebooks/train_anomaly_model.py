"""
train_anomaly_model.py
------------------------
Trains an unsupervised anomaly-detection model over the same event stream.
This model complements the supervised intrusion classifier: it doesn't
need labels, so it can catch *novel* / unseen suspicious behavior that
doesn't match any known attack signature (e.g. a brand-new login pattern).

Usage:
    python train_anomaly_model.py
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder

DATA_PATH = Path(__file__).parent / "../data/security_events.csv"
MODEL_DIR = Path(__file__).parent / "../models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

FEATURES = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    "num_failed_logins", "logged_in", "wrong_fragment", "urgent", "hot",
]


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    X = df[FEATURES].copy()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("Training Isolation Forest (unsupervised)...")
    # contamination ~ expected proportion of anomalies in the traffic mix
    contamination = (df["label"] != "BENIGN").mean()
    model = IsolationForest(
        n_estimators=250,
        contamination=min(contamination, 0.3),
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    # anomaly_score: higher = more anomalous (we flip sklearn's sign convention)
    raw_scores = model.decision_function(X_scaled)
    anomaly_score = (-raw_scores - (-raw_scores).min()) / ((-raw_scores).max() - (-raw_scores).min())
    predictions = model.predict(X_scaled)  # -1 = anomaly, 1 = normal

    df["anomaly_score"] = anomaly_score.round(4)
    df["is_anomaly"] = predictions == -1

    # Sanity check: how well does "flagged as anomaly" line up with "is actually an attack"?
    true_attack = (df["label"] != "BENIGN")
    flagged = df["is_anomaly"]
    overlap = (true_attack & flagged).sum()
    print(f"\nTrue attacks in data:        {true_attack.sum():,}")
    print(f"Flagged as anomalies:        {flagged.sum():,}")
    print(f"Attacks correctly flagged:   {overlap:,} ({overlap / true_attack.sum():.1%} of all attacks)")

    joblib.dump(model, MODEL_DIR / "anomaly_model.pkl")
    joblib.dump(scaler, MODEL_DIR / "anomaly_scaler.pkl")

    summary = {
        "contamination_used": round(float(min(contamination, 0.3)), 4),
        "total_rows": len(df),
        "true_attacks": int(true_attack.sum()),
        "flagged_anomalies": int(flagged.sum()),
        "attacks_correctly_flagged": int(overlap),
        "attack_recall_via_anomaly": round(float(overlap / true_attack.sum()), 4),
    }
    with open(MODEL_DIR / "anomaly_model_metrics.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSaved model -> {MODEL_DIR / 'anomaly_model.pkl'}")
    print(f"Saved metrics -> {MODEL_DIR / 'anomaly_model_metrics.json'}")


if __name__ == "__main__":
    main()

"""
train_intrusion_model.py
-------------------------
Trains the core intrusion-detection model for the AI Security Operations
Copilot. Multiclass classifier: BENIGN / DDoS / PortScan / BruteForce / Botnet.

Usage:
    python train_intrusion_model.py
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score, precision_score, recall_score,
)
from xgboost import XGBClassifier

DATA_PATH = Path(__file__).parent / "../data/security_events.csv"
MODEL_DIR = Path(__file__).parent / "../models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

FEATURES = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "count", "srv_count", "same_srv_rate", "diff_srv_rate",
    "serror_rate", "rerror_rate", "num_failed_logins",
    "logged_in", "wrong_fragment", "urgent", "hot",
]


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    print(f"  {len(df):,} rows loaded")

    # Encode categorical feature
    proto_encoder = LabelEncoder()
    df["protocol_type_enc"] = proto_encoder.fit_transform(df["protocol_type"])

    feature_cols = [c for c in FEATURES if c != "protocol_type"] + ["protocol_type_enc"]
    X = df[feature_cols]

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["label"])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    print("\nTraining XGBoost classifier (class-weighted)...")
    print("  Using balanced sample weights to improve minority-class")
    print("  (Botnet, BruteForce) recall without sacrificing accuracy —")
    print("  see notebooks/experiment_class_weighting.py for the controlled")
    print("  comparison against an unweighted baseline.")
    from sklearn.utils.class_weight import compute_sample_weight
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.15,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, sample_weight=sample_weights)

    print("\nEvaluating on held-out test set...")
    y_pred = model.predict(X_test)
    class_names = label_encoder.classes_

    report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True)
    print(classification_report(y_test, y_pred, target_names=class_names))

    macro_f1 = f1_score(y_test, y_pred, average="macro")
    macro_recall = recall_score(y_test, y_pred, average="macro")
    macro_precision = precision_score(y_test, y_pred, average="macro")
    print(f"Macro F1: {macro_f1:.4f} | Macro Precision: {macro_precision:.4f} | Macro Recall: {macro_recall:.4f}")

    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix (rows=true, cols=predicted):")
    print(pd.DataFrame(cm, index=class_names, columns=class_names))

    # Feature importance
    importances = pd.Series(model.feature_importances_, index=feature_cols).sort_values(ascending=False)
    print("\nTop feature importances:")
    print(importances.head(8))

    # Save artifacts
    joblib.dump(model, MODEL_DIR / "intrusion_model.pkl")
    joblib.dump(label_encoder, MODEL_DIR / "label_encoder.pkl")
    joblib.dump(proto_encoder, MODEL_DIR / "proto_encoder.pkl")

    metrics_summary = {
        "macro_f1": round(macro_f1, 4),
        "macro_precision": round(macro_precision, 4),
        "macro_recall": round(macro_recall, 4),
        "class_report": report,
        "feature_importance": importances.round(4).to_dict(),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
    }
    with open(MODEL_DIR / "intrusion_model_metrics.json", "w") as f:
        json.dump(metrics_summary, f, indent=2)

    print(f"\nSaved model -> {MODEL_DIR / 'intrusion_model.pkl'}")
    print(f"Saved metrics -> {MODEL_DIR / 'intrusion_model_metrics.json'}")


if __name__ == "__main__":
    main()

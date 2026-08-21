"""
experiment_class_weighting.py
-------------------------------
Honest, controlled comparison on the SAME 60,000-row dataset and SAME
train/test split:
  1. Baseline XGBoost (current production model)
  2. Class-weighted XGBoost (sample_weight = inverse class frequency)

Goal: see if minority-class recall (Botnet, BruteForce) improves without
faking accuracy. Reports real numbers either way.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    recall_score, precision_score, balanced_accuracy_score, accuracy_score,
)
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

DATA_PATH = Path(__file__).parent / "../data/security_events.csv"

FEATURES = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "count", "srv_count", "same_srv_rate", "diff_srv_rate",
    "serror_rate", "rerror_rate", "num_failed_logins",
    "logged_in", "wrong_fragment", "urgent", "hot",
]


def load_data():
    df = pd.read_csv(DATA_PATH)
    proto_encoder = LabelEncoder()
    df["protocol_type_enc"] = proto_encoder.fit_transform(df["protocol_type"])
    feature_cols = [c for c in FEATURES if c != "protocol_type"] + ["protocol_type_enc"]
    X = df[feature_cols]
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["label"])
    return X, y, label_encoder, feature_cols


def evaluate(name, model, X_test, y_test, class_names):
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    bal_acc = balanced_accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    macro_recall = recall_score(y_test, y_pred, average="macro")
    per_class_recall = recall_score(y_test, y_pred, average=None)

    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    print(f"Accuracy:          {acc:.4f}")
    print(f"Balanced Accuracy: {bal_acc:.4f}")
    print(f"Macro F1:          {macro_f1:.4f}")
    print(f"Macro Recall:      {macro_recall:.4f}")
    print("\nPer-class recall:")
    for cls, rec in zip(class_names, per_class_recall):
        print(f"  {cls:12s}: {rec:.4f}")
    print("\nFull report:")
    print(classification_report(y_test, y_pred, target_names=class_names))

    return {
        "accuracy": round(float(acc), 4),
        "balanced_accuracy": round(float(bal_acc), 4),
        "macro_f1": round(float(macro_f1), 4),
        "macro_recall": round(float(macro_recall), 4),
        "per_class_recall": {c: round(float(r), 4) for c, r in zip(class_names, per_class_recall)},
    }


def main():
    X, y, label_encoder, feature_cols = load_data()
    class_names = label_encoder.classes_

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    results = {}

    # --- Experiment 1: Baseline (current production model config) ---
    baseline = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.15,
        subsample=0.9, colsample_bytree=0.9,
        eval_metric="mlogloss", random_state=42, n_jobs=-1,
    )
    baseline.fit(X_train, y_train)
    results["baseline"] = evaluate("BASELINE (unweighted)", baseline, X_test, y_test, class_names)

    # --- Experiment 2: Class-weighted (balanced sample weights) ---
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
    weighted = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.15,
        subsample=0.9, colsample_bytree=0.9,
        eval_metric="mlogloss", random_state=42, n_jobs=-1,
    )
    weighted.fit(X_train, y_train, sample_weight=sample_weights)
    results["class_weighted"] = evaluate("CLASS-WEIGHTED", weighted, X_test, y_test, class_names)

    # --- Summary comparison ---
    print(f"\n{'='*60}")
    print("  SIDE-BY-SIDE COMPARISON")
    print(f"{'='*60}")
    print(f"{'Metric':<22} {'Baseline':>12} {'Weighted':>12}")
    for k in ["accuracy", "balanced_accuracy", "macro_f1", "macro_recall"]:
        print(f"{k:<22} {results['baseline'][k]:>12.4f} {results['class_weighted'][k]:>12.4f}")
    print("\nPer-class recall comparison:")
    for cls in class_names:
        b = results["baseline"]["per_class_recall"][cls]
        w = results["class_weighted"]["per_class_recall"][cls]
        delta = w - b
        print(f"  {cls:12s}: baseline={b:.4f}  weighted={w:.4f}  delta={delta:+.4f}")

    with open(Path(__file__).parent / "../models/experiment_comparison.json", "w") as f:
        json.dump(results, f, indent=2)

    return results, weighted, label_encoder, feature_cols, X_test, y_test


if __name__ == "__main__":
    main()

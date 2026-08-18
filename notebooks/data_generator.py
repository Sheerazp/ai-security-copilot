"""
data_generator.py
------------------
Generates a realistic, labeled network-traffic / security-event dataset
for the AI Security Operations Copilot project.

Why synthetic data?
Kaggle (source of the real CICIDS2017 dataset) is not reachable from this
build environment. This generator creates statistically realistic traffic
with the SAME feature structure as CICIDS2017/NSL-KDD, with clearly
separable but noisy attack patterns -- good enough to train and demo
real detection models. Swap in the real CICIDS2017 CSV later (same
column names) to retrain on real data without changing any other code.

Usage:
    python data_generator.py --rows 60000 --seed 42
"""

import argparse
import numpy as np
import pandas as pd
from pathlib import Path

FEATURE_COLUMNS = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "count", "srv_count", "same_srv_rate", "diff_srv_rate",
    "serror_rate", "rerror_rate", "num_failed_logins",
    "logged_in", "wrong_fragment", "urgent", "hot",
]

PROTOCOLS = ["tcp", "udp", "icmp"]

LABELS = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet"]
SEVERITY_MAP = {
    "BENIGN": "normal",
    "PortScan": "suspicious",
    "BruteForce": "suspicious",
    "Botnet": "critical",
    "DDoS": "critical",
}


def _rng(seed):
    return np.random.default_rng(seed)


def generate_benign(n, rng):
    return pd.DataFrame({
        "duration": rng.exponential(2.0, n).round(3),
        "protocol_type": rng.choice(PROTOCOLS, n, p=[0.75, 0.20, 0.05]),
        "src_bytes": rng.normal(500, 150, n).clip(20, None).round(0),
        "dst_bytes": rng.normal(700, 200, n).clip(20, None).round(0),
        "count": rng.poisson(3, n),
        "srv_count": rng.poisson(3, n),
        "same_srv_rate": rng.uniform(0.7, 1.0, n).round(3),
        "diff_srv_rate": rng.uniform(0.0, 0.2, n).round(3),
        "serror_rate": rng.uniform(0.0, 0.05, n).round(3),
        "rerror_rate": rng.uniform(0.0, 0.05, n).round(3),
        "num_failed_logins": rng.poisson(0.05, n),
        "logged_in": rng.choice([0, 1], n, p=[0.3, 0.7]),
        "wrong_fragment": np.zeros(n, dtype=int),
        "urgent": np.zeros(n, dtype=int),
        "hot": rng.poisson(0.1, n),
        "label": "BENIGN",
    })


def generate_ddos(n, rng):
    return pd.DataFrame({
        "duration": rng.exponential(0.05, n).round(3),
        "protocol_type": rng.choice(PROTOCOLS, n, p=[0.5, 0.45, 0.05]),
        "src_bytes": rng.normal(60, 20, n).clip(1, None).round(0),
        "dst_bytes": rng.normal(20, 10, n).clip(0, None).round(0),
        "count": rng.poisson(400, n),
        "srv_count": rng.poisson(380, n),
        "same_srv_rate": rng.uniform(0.9, 1.0, n).round(3),
        "diff_srv_rate": rng.uniform(0.0, 0.05, n).round(3),
        "serror_rate": rng.uniform(0.6, 1.0, n).round(3),
        "rerror_rate": rng.uniform(0.0, 0.2, n).round(3),
        "num_failed_logins": np.zeros(n, dtype=int),
        "logged_in": np.zeros(n, dtype=int),
        "wrong_fragment": rng.poisson(0.3, n),
        "urgent": np.zeros(n, dtype=int),
        "hot": np.zeros(n, dtype=int),
        "label": "DDoS",
    })


def generate_portscan(n, rng):
    return pd.DataFrame({
        "duration": rng.exponential(0.02, n).round(3),
        "protocol_type": rng.choice(PROTOCOLS, n, p=[0.85, 0.10, 0.05]),
        "src_bytes": rng.normal(40, 10, n).clip(1, None).round(0),
        "dst_bytes": rng.normal(0, 2, n).clip(0, None).round(0),
        "count": rng.poisson(150, n),
        "srv_count": rng.poisson(140, n),
        "same_srv_rate": rng.uniform(0.0, 0.3, n).round(3),
        "diff_srv_rate": rng.uniform(0.7, 1.0, n).round(3),
        "serror_rate": rng.uniform(0.3, 0.8, n).round(3),
        "rerror_rate": rng.uniform(0.4, 0.9, n).round(3),
        "num_failed_logins": np.zeros(n, dtype=int),
        "logged_in": np.zeros(n, dtype=int),
        "wrong_fragment": np.zeros(n, dtype=int),
        "urgent": np.zeros(n, dtype=int),
        "hot": np.zeros(n, dtype=int),
        "label": "PortScan",
    })


def generate_bruteforce(n, rng):
    return pd.DataFrame({
        "duration": rng.exponential(1.0, n).round(3),
        "protocol_type": np.full(n, "tcp"),
        "src_bytes": rng.normal(80, 20, n).clip(1, None).round(0),
        "dst_bytes": rng.normal(60, 15, n).clip(0, None).round(0),
        "count": rng.poisson(25, n),
        "srv_count": rng.poisson(25, n),
        "same_srv_rate": rng.uniform(0.8, 1.0, n).round(3),
        "diff_srv_rate": rng.uniform(0.0, 0.1, n).round(3),
        "serror_rate": rng.uniform(0.0, 0.1, n).round(3),
        "rerror_rate": rng.uniform(0.1, 0.3, n).round(3),
        "num_failed_logins": rng.poisson(8, n),
        "logged_in": rng.choice([0, 1], n, p=[0.85, 0.15]),
        "wrong_fragment": np.zeros(n, dtype=int),
        "urgent": np.zeros(n, dtype=int),
        "hot": rng.poisson(0.5, n),
        "label": "BruteForce",
    })


def generate_botnet(n, rng):
    return pd.DataFrame({
        "duration": rng.exponential(5.0, n).round(3),
        "protocol_type": rng.choice(PROTOCOLS, n, p=[0.6, 0.35, 0.05]),
        "src_bytes": rng.normal(300, 100, n).clip(1, None).round(0),
        "dst_bytes": rng.normal(1200, 400, n).clip(0, None).round(0),
        "count": rng.poisson(15, n),
        "srv_count": rng.poisson(10, n),
        "same_srv_rate": rng.uniform(0.4, 0.8, n).round(3),
        "diff_srv_rate": rng.uniform(0.2, 0.6, n).round(3),
        "serror_rate": rng.uniform(0.0, 0.2, n).round(3),
        "rerror_rate": rng.uniform(0.0, 0.2, n).round(3),
        "num_failed_logins": rng.poisson(0.2, n),
        "logged_in": rng.choice([0, 1], n, p=[0.5, 0.5]),
        "wrong_fragment": np.zeros(n, dtype=int),
        "urgent": rng.poisson(0.1, n),
        "hot": rng.poisson(1.0, n),
        "label": "Botnet",
    })


def generate_dataset(n_rows: int, seed: int = 42) -> pd.DataFrame:
    rng = _rng(seed)
    # Realistic class imbalance: mostly benign, attacks are the minority
    weights = {"BENIGN": 0.82, "DDoS": 0.06, "PortScan": 0.07, "BruteForce": 0.03, "Botnet": 0.02}
    counts = {k: int(n_rows * w) for k, w in weights.items()}
    # fix rounding so total == n_rows
    counts["BENIGN"] += n_rows - sum(counts.values())

    parts = [
        generate_benign(counts["BENIGN"], rng),
        generate_ddos(counts["DDoS"], rng),
        generate_portscan(counts["PortScan"], rng),
        generate_bruteforce(counts["BruteForce"], rng),
        generate_botnet(counts["Botnet"], rng),
    ]
    df = pd.concat(parts, ignore_index=True)

    # --- Inject real-world noise so the problem isn't trivially separable ---
    numeric_cols = [
        "duration", "src_bytes", "dst_bytes", "count", "srv_count",
        "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    ]
    for col in numeric_cols:
        noise = rng.normal(0, df[col].std() * 0.35 + 1e-6, len(df))
        df[col] = (df[col] + noise).clip(lower=0)

    # Clip rate-style columns back to [0, 1]
    for col in ["same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate"]:
        df[col] = df[col].clip(0, 1).round(3)

    # Randomly mislabel a small fraction of rows (sensor/labeling noise,
    # and genuinely ambiguous borderline traffic) -- keeps the model honest
    flip_frac = 0.035
    flip_idx = rng.choice(len(df), size=int(len(df) * flip_frac), replace=False)
    all_labels = np.array(LABELS)
    for i in flip_idx:
        df.loc[i, "label"] = rng.choice(all_labels)

    df["severity"] = df["label"].map(SEVERITY_MAP)

    # Add a synthetic timestamp column, spread across the last 48 hours
    now = pd.Timestamp.now()
    offsets = rng.integers(0, 48 * 3600, size=len(df))
    df["timestamp"] = [now - pd.Timedelta(seconds=int(o)) for o in offsets]

    # Add fake source/destination IPs.
    # Benign traffic: many distinct IPs (normal diverse users).
    # Attack traffic: drawn from a SMALL pool of "attacker" IPs per attack
    # type, and clustered in time -- this is what makes correlation
    # (multiple related events from the same source close in time) possible,
    # just like real botnets/scanners repeatedly hitting from the same hosts.
    def rand_ip(rng):
        return ".".join(str(rng.integers(1, 255)) for _ in range(4))

    benign_ip_pool = [rand_ip(rng) for _ in range(2000)]
    attacker_ip_pool = {label: [rand_ip(rng) for _ in range(6)] for label in LABELS if label != "BENIGN"}

    src_ips = []
    for label in df["label"]:
        if label == "BENIGN":
            src_ips.append(rng.choice(benign_ip_pool))
        else:
            src_ips.append(rng.choice(attacker_ip_pool[label]))
    df["src_ip"] = src_ips
    df["dst_ip"] = [rand_ip(rng) for _ in range(len(df))]

    # Cluster attack timestamps: each attacker IP operates in short bursts
    # (a scan or flood lasting a few minutes), not spread randomly across 48h.
    for label, ips in attacker_ip_pool.items():
        mask = df["label"] == label
        for ip in ips:
            ip_mask = mask & (df["src_ip"] == ip)
            n_ip = ip_mask.sum()
            if n_ip == 0:
                continue
            burst_start = now - pd.Timedelta(seconds=int(rng.integers(0, 48 * 3600)))
            burst_offsets = rng.integers(0, 8 * 60, size=n_ip)  # within an 8-minute burst
            df.loc[ip_mask, "timestamp"] = [burst_start + pd.Timedelta(seconds=int(o)) for o in burst_offsets]

    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=60000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=str, default="../data/security_events.csv")
    args = parser.parse_args()

    df = generate_dataset(args.rows, args.seed)
    out_path = Path(__file__).parent / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    print(f"Generated {len(df):,} rows -> {out_path}")
    print("\nLabel distribution:")
    print(df["label"].value_counts())
    print("\nSeverity distribution:")
    print(df["severity"].value_counts())

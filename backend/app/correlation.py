"""
correlation_engine.py
-----------------------
Groups related security events (same source IP, close in time) into a
single "possible attack campaign" instead of leaving analysts to look at
dozens of disconnected alerts one by one.

Logic:
  1. Take all events flagged suspicious/critical by the detection models.
  2. Group by src_ip.
  3. Within each src_ip group, cluster events that occur within a
     configurable time window (default: 10 minutes) of each other.
  4. Any cluster with >= MIN_EVENTS_FOR_CAMPAIGN events becomes a
     "campaign" with an aggregated severity and a human-readable summary.

This file is imported directly by the FastAPI backend (see
backend/app/correlation.py, which re-exports this logic).
"""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import List

import pandas as pd

MIN_EVENTS_FOR_CAMPAIGN = 3
TIME_WINDOW_MINUTES = 10


@dataclass
class Campaign:
    src_ip: str
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    event_count: int
    attack_types: List[str]
    max_severity: str
    event_indices: List[int] = field(default_factory=list)

    def summary(self) -> str:
        types = ", ".join(sorted(set(self.attack_types)))
        duration = (self.end_time - self.start_time).total_seconds() / 60
        return (
            f"Source {self.src_ip} triggered {self.event_count} related events "
            f"({types}) over {duration:.1f} minutes — flagged as a possible "
            f"coordinated attack campaign (severity: {self.max_severity})."
        )


_SEVERITY_RANK = {"normal": 0, "suspicious": 1, "critical": 2}


def _highest_severity(severities: List[str]) -> str:
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))


def find_campaigns(
    events: pd.DataFrame,
    time_window_minutes: int = TIME_WINDOW_MINUTES,
    min_events: int = MIN_EVENTS_FOR_CAMPAIGN,
) -> List[Campaign]:
    """
    events: DataFrame with at least ['src_ip', 'timestamp', 'label', 'severity']
    Only suspicious/critical events should be passed in (filter before calling).
    """
    campaigns: List[Campaign] = []
    if events.empty:
        return campaigns

    events = events.sort_values("timestamp")
    window = timedelta(minutes=time_window_minutes)

    for src_ip, group in events.groupby("src_ip"):
        group = group.sort_values("timestamp").reset_index()
        cluster_start = 0
        for i in range(1, len(group) + 1):
            is_last = i == len(group)
            gap_too_big = (
                not is_last
                and (group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"]) > window
            )
            if is_last or gap_too_big:
                cluster = group.iloc[cluster_start:i]
                if len(cluster) >= min_events:
                    campaigns.append(Campaign(
                        src_ip=src_ip,
                        start_time=cluster["timestamp"].min(),
                        end_time=cluster["timestamp"].max(),
                        event_count=len(cluster),
                        attack_types=cluster["label"].tolist(),
                        max_severity=_highest_severity(cluster["severity"].tolist()),
                        event_indices=cluster["index"].tolist(),
                    ))
                cluster_start = i

    campaigns.sort(key=lambda c: (_SEVERITY_RANK[c.max_severity], c.event_count), reverse=True)
    return campaigns


if __name__ == "__main__":
    # Quick smoke test against the generated dataset
    df = pd.read_csv("../data/security_events.csv", parse_dates=["timestamp"])
    suspicious = df[df["severity"] != "normal"]
    campaigns = find_campaigns(suspicious)
    print(f"Found {len(campaigns)} candidate campaigns from {len(suspicious):,} suspicious/critical events\n")
    for c in campaigns[:5]:
        print("-", c.summary())

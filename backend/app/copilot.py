import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from google import genai
from google.genai import types

from .database import SecurityEvent
from . import correlation as corr


try:
    _client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY")
    )
except Exception:
    _client = None


MODEL_NAME = "gemini-3.6-flash"


SYSTEM_PROMPT = """
You are a defensive Security Operations Copilot.

Use ONLY the security evidence provided by the backend.

You are READ-ONLY:
- Do not block IPs.
- Do not disable accounts.
- Do not modify systems.
- Never claim to have taken an action.

Never invent events, IP addresses, counts, timestamps, severity,
confidence values, or attack campaigns.

Give concise, professional SOC analysis.
Always finish with 1-3 recommended next steps for the human analyst.
"""


def _fetch_recent_events(
    db: Session,
    hours: int = 24,
    severity: str = "any",
    limit: int = 30,
) -> List[Dict[str, Any]]:

    hours = max(1, min(int(hours), 168))
    limit = max(1, min(int(limit), 100))

    cutoff = datetime.utcnow() - timedelta(hours=hours)

    query = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.timestamp >= cutoff)
    )

    if severity != "any":
        query = query.filter(SecurityEvent.severity == severity)

    rows = (
        query
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": row.id,
            "timestamp": row.timestamp.isoformat(),
            "src_ip": row.src_ip,
            "dst_ip": row.dst_ip,
            "predicted_label": row.predicted_label,
            "severity": row.severity,
            "confidence": row.confidence,
            "anomaly_score": row.anomaly_score,
            "is_anomaly": row.is_anomaly,
        }
        for row in rows
    ]


def _get_severity_summary(
    db: Session,
    hours: int = 24,
) -> Dict[str, Any]:

    hours = max(1, min(int(hours), 168))
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    base = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.timestamp >= cutoff)
    )

    by_severity = dict(
        base.with_entities(
            SecurityEvent.severity,
            func.count(SecurityEvent.id),
        )
        .group_by(SecurityEvent.severity)
        .all()
    )

    by_attack_type = dict(
        base.with_entities(
            SecurityEvent.predicted_label,
            func.count(SecurityEvent.id),
        )
        .group_by(SecurityEvent.predicted_label)
        .all()
    )

    return {
        "hours": hours,
        "total_events": base.count(),
        "by_severity": by_severity,
        "by_attack_type": by_attack_type,
    }


def _correlate_events(
    db: Session,
    hours: int = 24,
) -> Dict[str, Any]:

    hours = max(1, min(int(hours), 168))
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    rows = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.timestamp >= cutoff,
            SecurityEvent.severity != "normal",
        )
        .all()
    )

    if not rows:
        return {
            "total_campaigns": 0,
            "campaigns": [],
        }

    import pandas as pd

    df = pd.DataFrame([
        {
            "src_ip": row.src_ip,
            "timestamp": row.timestamp,
            "label": row.predicted_label,
            "severity": row.severity,
        }
        for row in rows
    ])

    if df.empty:
        return {
            "total_campaigns": 0,
            "campaigns": [],
        }

    campaigns = corr.find_campaigns(df)

    return {
        "total_campaigns": len(campaigns),
        "campaigns": [
            {
                "src_ip": campaign.src_ip,
                "event_count": campaign.event_count,
                "attack_types": list(set(campaign.attack_types)),
                "max_severity": campaign.max_severity,
                "summary": campaign.summary(),
            }
            for campaign in campaigns[:10]
        ],
    }


def ask_copilot(
    db: Session,
    question: str,
) -> Dict[str, Any]:

    if _client is None or not os.environ.get("GEMINI_API_KEY"):
        return {
            "answer": (
                "Gemini is not configured. "
                "Please set GEMINI_API_KEY in Railway Variables."
            ),
            "evidence_event_ids": [],
            "tools_used": [],
        }

    try:
        recent_events = _fetch_recent_events(
            db=db,
            hours=24,
            severity="any",
            limit=30,
        )

        severity_summary = _get_severity_summary(
            db=db,
            hours=24,
        )

        campaigns = _correlate_events(
            db=db,
            hours=24,
        )

        evidence_ids = [
            event["id"]
            for event in recent_events
            if "id" in event
        ]

        prompt = f"""
{SYSTEM_PROMPT}

ANALYST QUESTION:
{question}

SECURITY EVIDENCE:

SEVERITY SUMMARY:
{severity_summary}

RECENT EVENTS:
{recent_events}

CORRELATED CAMPAIGNS:
{campaigns}

Answer the analyst using ONLY this evidence.
"""

        response = _client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=1000,
            ),
        )

        answer = response.text or "No response was generated."

        return {
            "answer": answer,
            "evidence_event_ids": evidence_ids,
            "tools_used": [
                "fetch_recent_events",
                "get_severity_summary",
                "correlate_events",
            ],
        }

    except Exception as exc:
        return {
            "answer": (
                "The Security Copilot encountered an error: "
                f"{type(exc).__name__}: {str(exc)}"
            ),
            "evidence_event_ids": [],
            "tools_used": [],
        }

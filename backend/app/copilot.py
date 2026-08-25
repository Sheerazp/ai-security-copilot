from google import genai
from google.genai import types
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from .database import SecurityEvent
from . import correlation as corr


try:
    _client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY")
    )
except Exception:
    _client = None


MODEL_NAME = "gemini-2.5-flash"


SYSTEM_PROMPT = """
You are a defensive Security Operations Copilot embedded in a SOC dashboard.

Use ONLY evidence retrieved from the provided read-only security tools.

Never invent events, IPs, counts, timestamps, severity, confidence,
or campaign information.

You are READ-ONLY:
- Never block an IP.
- Never ban an IP.
- Never disable an account.
- Never modify system state.
- Never claim that you performed an action.

Always finish with 1-3 concrete recommended next steps for the human analyst.
Be concise, specific, and professional.
"""


def _fetch_recent_events(
    db: Session,
    hours: int = 24,
    severity: str = "any",
    limit: int = 20,
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

    by_label = dict(
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
        "by_attack_type": by_label,
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
                "The Security Copilot is not configured yet. "
                "Please configure GEMINI_API_KEY in Railway Variables."
            ),
            "evidence_event_ids": [],
            "tools_used": [],
        }

    tools_used = []
    evidence_ids = []

    def fetch_recent_events(
        hours: int = 24,
        severity: str = "any",
        limit: int = 20,
    ):
        tools_used.append("fetch_recent_events")

        result = _fetch_recent_events(
            db=db,
            hours=hours,
            severity=severity,
            limit=limit,
        )

        evidence_ids.extend(
            item["id"]
            for item in result
            if "id" in item
        )

        return {
            "events": result,
            "total_returned": len(result),
        }

    def get_severity_summary(hours: int = 24):
        tools_used.append("get_severity_summary")

        return _get_severity_summary(
            db=db,
            hours=hours,
        )

    def correlate_events(hours: int = 24):
        tools_used.append("correlate_events")

        return _correlate_events(
            db=db,
            hours=hours,
        )

    try:
        response = _client.models.generate_content(
            model=MODEL_NAME,
            contents=question,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
                max_output_tokens=1000,
                tools=[
                    fetch_recent_events,
                    get_severity_summary,
                    correlate_events,
                ],
                automatic_function_calling=(
                    types.AutomaticFunctionCallingConfig(
                        maximum_remote_calls=5
                    )
                ),
            ),
        )

        return {
            "answer": response.text or "No answer generated.",
            "evidence_event_ids": list(dict.fromkeys(evidence_ids)),
            "tools_used": list(dict.fromkeys(tools_used)),
        }

    except Exception as exc:
        return {
            "answer": (
                "The Security Copilot encountered an error: "
                f"{type(exc).__name__}"
            ),
            "evidence_event_ids": list(dict.fromkeys(evidence_ids)),
            "tools_used": list(dict.fromkeys(tools_used)),
        }

"""
copilot.py
-----------
The agentic layer. An analyst asks a plain-language question; the agent
calls read-only "tools" (backed by the real database) to gather evidence,
then writes an answer + recommended next steps.

GUARDRAIL (by design, not an afterthought):
The tools available to this agent are STRICTLY READ-ONLY. There is no
tool that blocks an IP, disables an account, or changes any system state.
The copilot informs and recommends -- a human always decides and acts.

Requires an Anthropic API key in the environment:
    export ANTHROPIC_API_KEY="sk-ant-..."
"""

import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from .database import SecurityEvent
from . import correlation as corr

try:
    import anthropic
    _client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
except Exception:
    _client = None

MODEL_NAME = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a defensive Security Operations Copilot embedded in a SOC dashboard.

Your job: help a human analyst understand what happened, using ONLY the tools
provided to retrieve real evidence from the event database. Never invent
events, IPs, or numbers that didn't come from a tool call.

Strict rules:
- You are READ-ONLY. You cannot block, ban, disable, or take any action.
- Always end your answer with 1-3 concrete recommended next steps for the
  human analyst to take -- you recommend, you never act.
- Be concise and specific: cite actual counts, IPs, and timeframes from
  the tool results, not vague language.
"""

TOOLS = [
    {
        "name": "fetch_recent_events",
        "description": "Fetch recent security events from the database, optionally filtered by severity and a time window in hours.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "description": "How many hours back to look", "default": 24},
                "severity": {"type": "string", "enum": ["normal", "suspicious", "critical", "any"], "default": "any"},
                "limit": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "get_severity_summary",
        "description": "Get counts of events by severity level and by attack type over a time window.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "default": 24},
            },
        },
    },
    {
        "name": "correlate_events",
        "description": "Run the threat-correlation engine to find groups of related events (same source, close in time) that may form a single attack campaign.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "default": 24},
            },
        },
    },
]


def _fetch_recent_events(db: Session, hours: int = 24, severity: str = "any", limit: int = 20) -> List[Dict]:
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff)
    if severity != "any":
        q = q.filter(SecurityEvent.severity == severity)
    rows = q.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": r.id, "timestamp": r.timestamp.isoformat(), "src_ip": r.src_ip,
            "dst_ip": r.dst_ip, "predicted_label": r.predicted_label,
            "severity": r.severity, "confidence": r.confidence,
        }
        for r in rows
    ]


def _get_severity_summary(db: Session, hours: int = 24) -> Dict:
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    base = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff)
    by_severity = dict(
        base.with_entities(SecurityEvent.severity, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.severity).all()
    )
    by_label = dict(
        base.with_entities(SecurityEvent.predicted_label, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.predicted_label).all()
    )
    return {"hours": hours, "by_severity": by_severity, "by_attack_type": by_label}


def _correlate_events(db: Session, hours: int = 24) -> Dict:
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.timestamp >= cutoff, SecurityEvent.severity != "normal")
        .all()
    )
    import pandas as pd
    df = pd.DataFrame([{
        "src_ip": r.src_ip, "timestamp": r.timestamp,
        "label": r.predicted_label, "severity": r.severity,
    } for r in rows])
    if df.empty:
        return {"total_campaigns": 0, "campaigns": []}
    campaigns = corr.find_campaigns(df)
    return {
        "total_campaigns": len(campaigns),
        "campaigns": [
            {
                "src_ip": c.src_ip, "event_count": c.event_count,
                "attack_types": list(set(c.attack_types)),
                "max_severity": c.max_severity, "summary": c.summary(),
            }
            for c in campaigns[:10]
        ],
    }


TOOL_DISPATCH = {
    "fetch_recent_events": _fetch_recent_events,
    "get_severity_summary": _get_severity_summary,
    "correlate_events": _correlate_events,
}


def ask_copilot(db: Session, question: str) -> Dict[str, Any]:
    if _client is None or not os.environ.get("ANTHROPIC_API_KEY"):
        return {
            "answer": (
                "The copilot's language model is not configured yet. "
                "Set the ANTHROPIC_API_KEY environment variable to enable "
                "natural-language analysis. (Detection, correlation, and the "
                "dashboard all work without it.)"
            ),
            "evidence_event_ids": [],
            "tools_used": [],
        }

    messages = [{"role": "user", "content": question}]
    tools_used = []
    evidence_ids = []

    for _ in range(5):  # cap tool-call loops as a safety limit
        response = _client.messages.create(
            model=MODEL_NAME,
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            final_text = "".join(b.text for b in response.content if b.type == "text")
            return {"answer": final_text, "evidence_event_ids": evidence_ids, "tools_used": tools_used}

        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            tools_used.append(block.name)
            fn = TOOL_DISPATCH.get(block.name)
            result = fn(db, **block.input) if fn else {"error": "unknown tool"}
            if isinstance(result, list):
                evidence_ids.extend([r["id"] for r in result if "id" in r])
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(result, default=str),
            })
        messages.append({"role": "user", "content": tool_results})

    return {
        "answer": "The analysis took too many steps to complete. Try a narrower question.",
        "evidence_event_ids": evidence_ids,
        "tools_used": tools_used,
    }

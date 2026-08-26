"""
main.py
--------
The AI Security Operations Copilot -- FastAPI backend.

Run locally:
    uvicorn app.main:app --reload

Endpoints:
    POST /detect          Score a single event (used by the simulator / real feed)
    GET  /events           Recent events, filterable by severity
    GET  /correlate        Run the correlation engine over recent events
    POST /copilot/ask      Ask the Security Copilot a question
    GET  /stats             Summary counts for the dashboard header
    WS   /ws/live           Live event stream (simulated) for the dashboard
"""

import asyncio
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

import pandas as pd
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from . import schemas, correlation as corr
from .database import init_db, get_db, SecurityEvent, SessionLocal
from .ml_service import ml_service
from .copilot import ask_copilot

app = FastAPI(
    title="AI Security Operations Copilot",
    description="Real-time threat detection + AI-assisted security analysis. Read-only by design.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your deployed frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_PATH = Path(__file__).parent.parent.parent / "data" / "security_events.csv"


@app.on_event("startup")
def on_startup():
    init_db()
    _seed_from_csv_if_empty()


def _seed_from_csv_if_empty():
    """On first boot, load the generated dataset into the DB so the
    dashboard and copilot have realistic historical data immediately."""
    db = SessionLocal()
    try:
        if db.query(SecurityEvent).first() is not None:
            return  # already seeded
        if not DATA_PATH.exists():
            return
        df = pd.read_csv(DATA_PATH, parse_dates=["timestamp"])
        df = df.sample(n=min(5000, len(df)), random_state=1)  # keep seed data light
        for _, row in df.iterrows():
            db.add(SecurityEvent(
                timestamp=row["timestamp"], src_ip=row["src_ip"], dst_ip=row["dst_ip"],
                protocol_type=row["protocol_type"], duration=row["duration"],
                src_bytes=row["src_bytes"], dst_bytes=row["dst_bytes"],
                count=int(row["count"]), srv_count=int(row["srv_count"]),
                same_srv_rate=row["same_srv_rate"], diff_srv_rate=row["diff_srv_rate"],
                serror_rate=row["serror_rate"], rerror_rate=row["rerror_rate"],
                num_failed_logins=int(row["num_failed_logins"]), logged_in=int(row["logged_in"]),
                wrong_fragment=int(row["wrong_fragment"]), urgent=int(row["urgent"]),
                hot=int(row["hot"]), predicted_label=row["label"], severity=row["severity"],
                confidence=0.95, anomaly_score=0.5, is_anomaly=row["severity"] != "normal",
            ))
        db.commit()
        print(f"Seeded database with {len(df):,} historical events.")
    finally:
        db.close()


@app.get("/")
def root():
    return {"status": "ok", "service": "AI Security Operations Copilot API"}


@app.post("/detect", response_model=schemas.EventResult)
def detect(event: schemas.EventInput, db: Session = Depends(get_db)):
    result = ml_service.score_event(event.dict())
    db_event = SecurityEvent(
        timestamp=datetime.utcnow(), **event.dict(), **{
            k: v for k, v in result.items()
        }
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return schemas.EventResult(
        id=db_event.id, timestamp=db_event.timestamp, src_ip=db_event.src_ip,
        dst_ip=db_event.dst_ip, predicted_label=db_event.predicted_label,
        severity=db_event.severity, confidence=db_event.confidence,
        anomaly_score=db_event.anomaly_score, is_anomaly=db_event.is_anomaly,
    )


@app.get("/events", response_model=schemas.EventsResponse)
def get_events(severity: str = "any", hours: int = 24, limit: int = 100, db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff)
    if severity != "any":
        q = q.filter(SecurityEvent.severity == severity)
    total = q.count()
    rows = q.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    events = [
        schemas.EventResult(
            id=r.id, timestamp=r.timestamp, src_ip=r.src_ip, dst_ip=r.dst_ip,
            predicted_label=r.predicted_label, severity=r.severity,
            confidence=r.confidence, anomaly_score=r.anomaly_score, is_anomaly=r.is_anomaly,
        ) for r in rows
    ]
    return schemas.EventsResponse(total=total, events=events)


@app.get("/correlate", response_model=schemas.CorrelateResponse)
def correlate(hours: int = 24, db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.timestamp >= cutoff, SecurityEvent.severity != "normal")
        .all()
    )
    df = pd.DataFrame([{
        "src_ip": r.src_ip, "timestamp": r.timestamp,
        "label": r.predicted_label, "severity": r.severity,
    } for r in rows])
    if df.empty:
        return schemas.CorrelateResponse(total_campaigns=0, campaigns=[])
    campaigns = corr.find_campaigns(df)
    return schemas.CorrelateResponse(
        total_campaigns=len(campaigns),
        campaigns=[
            schemas.CampaignResult(
                src_ip=c.src_ip, start_time=c.start_time, end_time=c.end_time,
                event_count=c.event_count, attack_types=list(set(c.attack_types)),
                max_severity=c.max_severity, summary=c.summary(),
            ) for c in campaigns
        ],
    )


@app.post("/copilot/ask", response_model=schemas.CopilotResponse)
def copilot_ask(request: schemas.CopilotRequest, db: Session = Depends(get_db)):
    result = ask_copilot(db, request.question)
    return schemas.CopilotResponse(**result)


@app.get("/stats", response_model=schemas.StatsResponse)
def stats(hours: int = 24, db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    base = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff)
    total = base.count()
    counts = dict(base.with_entities(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity).all())
    campaigns = correlate(hours=hours, db=db)
    return schemas.StatsResponse(
        total_events=total,
        normal=counts.get("normal", 0),
        suspicious=counts.get("suspicious", 0),
        critical=counts.get("critical", 0),
        active_campaigns=campaigns.total_campaigns,
    )


# ---------------------------------------------------------------------------
# Live simulated stream (WebSocket) -- stands in for a real traffic feed.
# Replace `_simulate_event()` with a real packet-capture / log-tailing
# source when connecting this to actual infrastructure.
# ---------------------------------------------------------------------------

def _simulate_event() -> dict:
    profiles = {
        "normal": dict(duration=random.uniform(0.5, 3), src_bytes=random.uniform(300, 700),
                       dst_bytes=random.uniform(400, 900), count=random.randint(1, 6),
                       srv_count=random.randint(1, 6), same_srv_rate=random.uniform(0.7, 1),
                       diff_srv_rate=random.uniform(0, 0.2), serror_rate=random.uniform(0, 0.05),
                       rerror_rate=random.uniform(0, 0.05), num_failed_logins=0, logged_in=1,
                       wrong_fragment=0, urgent=0, hot=0, protocol_type="tcp"),
        "ddos": dict(duration=random.uniform(0.01, 0.1), src_bytes=random.uniform(30, 90),
                     dst_bytes=random.uniform(0, 30), count=random.randint(300, 500),
                     srv_count=random.randint(300, 480), same_srv_rate=random.uniform(0.9, 1),
                     diff_srv_rate=random.uniform(0, 0.05), serror_rate=random.uniform(0.6, 1),
                     rerror_rate=random.uniform(0, 0.2), num_failed_logins=0, logged_in=0,
                     wrong_fragment=0, urgent=0, hot=0, protocol_type="udp"),
        "bruteforce": dict(duration=random.uniform(0.5, 2), src_bytes=random.uniform(60, 100),
                            dst_bytes=random.uniform(40, 80), count=random.randint(15, 35),
                            srv_count=random.randint(15, 35), same_srv_rate=random.uniform(0.8, 1),
                            diff_srv_rate=random.uniform(0, 0.1), serror_rate=random.uniform(0, 0.1),
                            rerror_rate=random.uniform(0.1, 0.3), num_failed_logins=random.randint(5, 12),
                            logged_in=0, wrong_fragment=0, urgent=0, hot=1, protocol_type="tcp"),
    }
    weights = [0.85, 0.08, 0.07]
    profile_name = random.choices(list(profiles.keys()), weights=weights)[0]
    event = profiles[profile_name]
    event["src_ip"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    event["dst_ip"] = f"10.0.0.{random.randint(1,20)}"
    return event


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    db = SessionLocal()
    try:
        while True:
            raw_event = _simulate_event()
            result = ml_service.score_event(raw_event)

            db_event = SecurityEvent(timestamp=datetime.utcnow(), **raw_event, **result)
            db.add(db_event)
            db.commit()
            db.refresh(db_event)

            payload = {
                "id": db_event.id, "timestamp": db_event.timestamp.isoformat(),
                "src_ip": db_event.src_ip, "dst_ip": db_event.dst_ip,
                "predicted_label": db_event.predicted_label, "severity": db_event.severity,
                "confidence": db_event.confidence, "is_anomaly": db_event.is_anomaly,
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(1.2)
    except WebSocketDisconnect:
        pass
    finally:
        db.close()


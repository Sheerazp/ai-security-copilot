"""schemas.py -- request/response models for the API."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class EventInput(BaseModel):
    """Raw network/log event submitted for scoring."""
    src_ip: str = Field(..., example="192.168.1.45")
    dst_ip: str = Field(..., example="10.0.0.5")
    protocol_type: str = Field("tcp", example="tcp")
    duration: float = 0.0
    src_bytes: float = 0.0
    dst_bytes: float = 0.0
    count: int = 0
    srv_count: int = 0
    same_srv_rate: float = 0.0
    diff_srv_rate: float = 0.0
    serror_rate: float = 0.0
    rerror_rate: float = 0.0
    num_failed_logins: int = 0
    logged_in: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    hot: int = 0


class EventResult(BaseModel):
    id: Optional[int] = None
    timestamp: datetime
    src_ip: str
    dst_ip: str
    predicted_label: str
    severity: str
    confidence: float
    anomaly_score: float
    is_anomaly: bool


class EventsResponse(BaseModel):
    total: int
    events: List[EventResult]


class CampaignResult(BaseModel):
    src_ip: str
    start_time: datetime
    end_time: datetime
    event_count: int
    attack_types: List[str]
    max_severity: str
    summary: str


class CorrelateResponse(BaseModel):
    total_campaigns: int
    campaigns: List[CampaignResult]


class CopilotRequest(BaseModel):
    question: str = Field(..., example="What was the most serious threat in the last 24 hours?")


class CopilotResponse(BaseModel):
    answer: str
    evidence_event_ids: List[int] = []
    tools_used: List[str] = []


class StatsResponse(BaseModel):
    total_events: int
    normal: int
    suspicious: int
    critical: int
    active_campaigns: int

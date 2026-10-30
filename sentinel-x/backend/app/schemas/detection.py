"""Intrusion Detection and Feedback Schemas (Section 18)."""

from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class DetectionAnalyzeRequest(BaseModel):
    """Trigger ML analysis on a specific ingested flow."""

    model_config = ConfigDict(extra="forbid")

    flow_id: str = Field(..., description="UUID of the network flow to analyze")


class DetectionAnalyzeData(BaseModel):
    """Immediate result of ML flow analysis."""

    detection_id: str
    attack_type: str
    confidence: float
    anomaly_score: Optional[float] = None
    risk_score: float
    severity: str


class DetectionFlowSummary(BaseModel):
    """Summary of flow telemetry linked to a detection."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    packets: Optional[int] = None
    bytes: Optional[int] = None
    duration_ms: Optional[Decimal] = None


class DetectionItem(BaseModel):
    """Detection item in paginated list."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    flow_id: str
    model_version_id: str
    attack_type: str
    confidence: float
    anomaly_score: Optional[float] = None
    risk_score: float
    severity: str
    is_anomaly: bool
    explanation: Optional[Dict[str, Any]] = None
    detected_at: datetime
    flow: Optional[DetectionFlowSummary] = None


class AnalystFeedbackRequest(BaseModel):
    """Analyst review feedback submission."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"]
    comment: Optional[str] = Field(None, max_length=1000)


class AnalystFeedbackResponse(BaseModel):
    """Recorded analyst feedback."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    detection_id: str
    analyst_id: str
    verdict: str
    comment: Optional[str] = None
    created_at: datetime


class DetectionDetailData(DetectionItem):
    """Comprehensive detection investigation payload."""

    feedback: List[AnalystFeedbackResponse] = []

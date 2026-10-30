"""Incident management and investigation schemas (Section 19)."""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.detection import DetectionItem


class IncidentCreateRequest(BaseModel):
    """Manually create or correlate a security incident."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    status: Optional[
        Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
    ] = "OPEN"
    detection_ids: List[str] = Field(
        default_factory=list, description="UUIDs of detections to attach"
    )


class IncidentUpdateRequest(BaseModel):
    """Update incident status, assignment, or notes."""

    model_config = ConfigDict(extra="ignore")

    status: Optional[
        Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
    ] = None
    assigned_to: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None


class IncidentEventCreateRequest(BaseModel):
    """Add a timeline event or analyst note to an incident."""

    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(..., min_length=2, max_length=50)
    message: str = Field(..., min_length=1, max_length=5000)
    metadata: Optional[Dict[str, Any]] = None


class IncidentEventResponse(BaseModel):
    """Timeline event representation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    event_type: str
    message: str
    metadata: Optional[Dict[str, Any]] = None
    actor_id: Optional[str] = None
    created_at: datetime


class IncidentItem(BaseModel):
    """Summary of security incident in collection."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assigned_to: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    detection_count: Optional[int] = 0


class IncidentDetailData(IncidentItem):
    """Full incident investigation details."""

    detections: List[DetectionItem] = []
    events: List[IncidentEventResponse] = []

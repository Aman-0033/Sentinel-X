"""Telemetry flow ingestion schemas (Section 17)."""

from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SingleFlowInput(BaseModel):
    """Raw network flow telemetry record."""

    model_config = ConfigDict(extra="ignore")

    timestamp: Optional[datetime] = None
    source_ip: str = Field(..., min_length=1, max_length=45)
    destination_ip: str = Field(..., min_length=1, max_length=45)
    source_port: Optional[int] = Field(None, ge=1, le=65535)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field("TCP", max_length=10)
    packets: Optional[int] = Field(None, ge=0)
    bytes: Optional[int] = Field(None, ge=0)
    duration_ms: Optional[Decimal] = Field(None, ge=Decimal(0))
    direction: Optional[str] = Field("INBOUND", max_length=20)
    features: Optional[Dict[str, Any]] = None


class BatchFlowIngestionRequest(BaseModel):
    """Batch of network flows submitted for ingestion and ML analysis."""

    model_config = ConfigDict(extra="forbid")

    source_id: Optional[str] = None
    flows: List[SingleFlowInput] = Field(..., min_length=1, max_length=1000)


class BatchIngestionData(BaseModel):
    """Response payload for ingested batch telemetry."""

    accepted: int
    rejected: int
    job_id: str


class UploadResponseData(BaseModel):
    """Response payload for file quarantine processing."""

    filename: str
    accepted: int
    status: str
    job_id: str

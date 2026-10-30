"""Report Generation Schemas (Section 22)."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ReportCreateRequest(BaseModel):
    """Request asynchronous report generation."""

    model_config = ConfigDict(extra="forbid")

    report_type: Literal["SECURITY_SUMMARY", "INCIDENT_FORENSICS"] = "SECURITY_SUMMARY"
    period_start: datetime
    period_end: datetime
    format: Literal["PDF", "CSV", "JSON"] = "JSON"
    incident_id: Optional[str] = Field(
        None, description="Target incident for INCIDENT_FORENSICS reports"
    )


class ReportItem(BaseModel):
    """Report status and metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    generated_by: str
    incident_id: Optional[str] = None
    period_start: datetime
    period_end: datetime
    format: str
    file_path: Optional[str] = None
    status: str
    created_at: datetime

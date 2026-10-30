"""Threat Intelligence request and response schemas (Section 20)."""

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ThreatIntelEnrichRequest(BaseModel):
    """Enrich an observable indicator."""

    model_config = ConfigDict(extra="forbid")

    indicator_type: Literal["ip", "domain", "hash"]
    indicator_value: str = Field(..., min_length=1, max_length=255)
    provider: Optional[Literal["virustotal", "abuseipdb"]] = "virustotal"


class ThreatIntelData(BaseModel):
    """Normalized threat intelligence indicator enrichment."""

    model_config = ConfigDict(from_attributes=True)

    indicator: str
    indicator_type: str
    provider: str
    reputation_score: Optional[float] = None
    verdict: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    checked_at: datetime
    response_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

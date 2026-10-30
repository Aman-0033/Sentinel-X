"""Base abstractions for Threat Intelligence enrichment (Section 8)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class ThreatIntelResult:
    """Standardized result returned by external threat-intel providers."""

    indicator: str
    indicator_type: str
    provider: str
    reputation_score: Optional[float]
    verdict: Optional[str]  # e.g. "MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"
    country: Optional[str]
    asn: Optional[int]
    response_data: Optional[Dict[str, Any]]
    checked_at: datetime
    expires_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        """Indicates if enrichment was successfully gathered without fatal error."""
        return self.error is None


class ThreatIntelProvider(ABC):
    """Abstract interface for external Threat Intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique identifier name for this provider."""
        pass

    @abstractmethod
    async def check_indicator(
        self, indicator: str, indicator_type: str = "ip"
    ) -> ThreatIntelResult:
        """Fetch threat intelligence for an indicator with timeout and safe fallback."""
        pass

"""Threat Intel application service."""

from typing import Optional

from sqlalchemy.orm import Session

from app.threat_intel.base import ThreatIntelResult
from app.threat_intel.service import ThreatIntelOrchestrator

_orchestrator = ThreatIntelOrchestrator()


class ThreatIntelService:
    """Application service for threat intelligence enrichment."""

    def __init__(self, db: Session, orchestrator: Optional[ThreatIntelOrchestrator] = None):
        self.db = db
        self.orchestrator = orchestrator or _orchestrator

    async def enrich_ip(
        self,
        ip_address: str,
        provider: str = "virustotal",
        detection_id: Optional[str] = None,
    ) -> ThreatIntelResult:
        """Enrich an IP address indicator."""
        return await self.orchestrator.enrich_indicator(
            indicator=ip_address,
            indicator_type="ip",
            preferred_provider=provider,
            db=self.db,
            detection_id=detection_id,
        )

    async def enrich_indicator(
        self,
        indicator: str,
        indicator_type: str = "ip",
        provider: str = "virustotal",
        detection_id: Optional[str] = None,
    ) -> ThreatIntelResult:
        """Enrich any supported indicator (ip, domain, hash)."""
        return await self.orchestrator.enrich_indicator(
            indicator=indicator,
            indicator_type=indicator_type,
            preferred_provider=provider,
            db=self.db,
            detection_id=detection_id,
        )

"""Threat Intelligence Enrichment Repository.

Data access layer for OSINT enrichments.
"""

from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models.threat_intel import ThreatIntelEnrichment


class ThreatIntelRepository:
    """Repository handling database operations for ThreatIntelEnrichment records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, enrichment_id: str) -> Optional[ThreatIntelEnrichment]:
        """Fetch enrichment record by primary key ID."""
        return (
            self.db.query(ThreatIntelEnrichment)
            .filter(ThreatIntelEnrichment.id == enrichment_id)
            .first()
        )

    def create(self, **kwargs) -> ThreatIntelEnrichment:
        """Persist a new threat-intel enrichment record."""
        enrichment = ThreatIntelEnrichment(**kwargs)
        self.db.add(enrichment)
        self.db.commit()
        self.db.refresh(enrichment)
        return enrichment

    def get_by_indicator(
        self, indicator_value: str, provider: Optional[str] = None
    ) -> Optional[ThreatIntelEnrichment]:
        """Fetch cached enrichment by indicator value and optional provider."""
        query = self.db.query(ThreatIntelEnrichment).filter(
            ThreatIntelEnrichment.indicator_value == indicator_value
        )
        if provider:
            query = query.filter(ThreatIntelEnrichment.provider == provider.upper())
        return query.order_by(ThreatIntelEnrichment.checked_at.desc()).first()

    def list_by_detection(self, detection_id: str) -> List[ThreatIntelEnrichment]:
        """Fetch all threat intelligence records associated with a detection."""
        return (
            self.db.query(ThreatIntelEnrichment)
            .filter(ThreatIntelEnrichment.detection_id == detection_id)
            .order_by(ThreatIntelEnrichment.checked_at.desc())
            .all()
        )

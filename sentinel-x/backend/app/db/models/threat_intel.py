"""Threat intelligence enrichment record."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSONB_TYPE, Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.detection import Detection


class ThreatIntelEnrichment(Base, UUIDPrimaryKeyMixin):
    """External threat intelligence enrichment record."""

    __tablename__ = "threat_intel_enrichments"
    __table_args__ = (Index("ix_threat_intel_enrichments_indicator_value", "indicator_value"),)

    detection_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    reputation_score: Mapped[Optional[Decimal]] = mapped_column(Numeric(6, 2), nullable=True)
    verdict: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)
    asn: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    response_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB_TYPE, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    detection: Mapped["Detection"] = relationship(
        "Detection", back_populates="threat_intel_enrichments"
    )

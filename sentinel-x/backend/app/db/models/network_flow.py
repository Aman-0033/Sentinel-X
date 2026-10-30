"""Network flow telemetry record model."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import INET_TYPE, JSONB_TYPE, Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.data_source import DataSource
    from app.db.models.detection import Detection


class NetworkFlow(Base, UUIDPrimaryKeyMixin):
    """Network flow entity capturing connection telemetry."""

    __tablename__ = "network_flows"
    __table_args__ = (
        CheckConstraint(
            "source_port IS NULL OR (source_port >= 1 AND source_port <= 65535)",
            name="ck_network_flows_source_port",
        ),
        CheckConstraint(
            "destination_port IS NULL OR (destination_port >= 1 AND destination_port <= 65535)",
            name="ck_network_flows_destination_port",
        ),
        CheckConstraint(
            "packets IS NULL OR packets >= 0",
            name="ck_network_flows_packets",
        ),
        CheckConstraint(
            "bytes IS NULL OR bytes >= 0",
            name="ck_network_flows_bytes",
        ),
        CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name="ck_network_flows_duration_ms",
        ),
        Index("ix_network_flows_timestamp", "timestamp"),
        Index("ix_network_flows_source_ip", "source_ip"),
        Index("ix_network_flows_destination_ip", "destination_ip"),
    )

    source_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("data_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str] = mapped_column(INET_TYPE, nullable=False)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str] = mapped_column(INET_TYPE, nullable=False)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    packets: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    duration_ms: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 3), nullable=True)
    direction: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    raw_features: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB_TYPE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    source: Mapped[Optional["DataSource"]] = relationship("DataSource", back_populates="flows")
    detections: Mapped[List["Detection"]] = relationship("Detection", back_populates="flow")

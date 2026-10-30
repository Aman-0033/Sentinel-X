"""Data source entity for telemetry ingestion."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSONB_TYPE, Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.network_flow import NetworkFlow
    from app.db.models.user import User


class DataSource(Base, UUIDPrimaryKeyMixin):
    """Telemetry data source configuration entity."""

    __tablename__ = "data_sources"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('DATASET', 'CSV_UPLOAD', 'JSON_UPLOAD', 'SIMULATOR', 'LIVE_COLLECTOR')",
            name="ck_data_sources_source_type",
        ),
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    configuration: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB_TYPE, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    creator: Mapped[Optional["User"]] = relationship("User", back_populates="data_sources")
    flows: Mapped[List["NetworkFlow"]] = relationship("NetworkFlow", back_populates="source")

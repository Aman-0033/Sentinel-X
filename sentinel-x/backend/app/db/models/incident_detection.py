"""Many-to-many association model linking incidents and detections."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.detection import Detection
    from app.db.models.incident import Incident


class IncidentDetection(Base):
    """Association entity linking security incidents with triggered detections."""

    __tablename__ = "incident_detections"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    detection_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("detections.id", ondelete="CASCADE"),
        primary_key=True,
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="detection_associations")
    detection: Mapped["Detection"] = relationship(
        "Detection", back_populates="incident_associations"
    )

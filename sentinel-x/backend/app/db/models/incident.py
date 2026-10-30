"""Security incident entity and investigation container."""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.detection import Detection
    from app.db.models.incident_detection import IncidentDetection
    from app.db.models.incident_event import IncidentEvent
    from app.db.models.report import Report
    from app.db.models.user import User


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Security incident record aggregating detections and timeline events."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')",
            name="ck_incidents_status",
        ),
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_incidents_severity",
        ),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_assigned_to", "assigned_to"),
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="OPEN", nullable=False)
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    assignee: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[assigned_to],
        back_populates="assigned_incidents",
    )
    creator: Mapped["User"] = relationship(
        "User",
        foreign_keys=[created_by],
        back_populates="created_incidents",
    )
    detection_associations: Mapped[List["IncidentDetection"]] = relationship(
        "IncidentDetection",
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    detections: Mapped[List["Detection"]] = relationship(
        "Detection",
        secondary="incident_detections",
        back_populates="incidents",
        viewonly=True,
    )
    events: Mapped[List["IncidentEvent"]] = relationship(
        "IncidentEvent",
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="incident")

"""User model for authentication and access control."""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.analyst_feedback import AnalystFeedback
    from app.db.models.audit_log import AuditLog
    from app.db.models.data_source import DataSource
    from app.db.models.incident import Incident
    from app.db.models.incident_event import IncidentEvent
    from app.db.models.model_version import ModelVersion
    from app.db.models.report import Report
    from app.db.models.role import Role


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """User account entity."""

    __tablename__ = "users"

    role_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    role: Mapped["Role"] = relationship("Role", back_populates="users")
    data_sources: Mapped[List["DataSource"]] = relationship("DataSource", back_populates="creator")
    model_versions: Mapped[List["ModelVersion"]] = relationship(
        "ModelVersion", back_populates="creator"
    )
    assigned_incidents: Mapped[List["Incident"]] = relationship(
        "Incident",
        foreign_keys="Incident.assigned_to",
        back_populates="assignee",
    )
    created_incidents: Mapped[List["Incident"]] = relationship(
        "Incident",
        foreign_keys="Incident.created_by",
        back_populates="creator",
    )
    incident_events: Mapped[List["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="actor"
    )
    analyst_feedback: Mapped[List["AnalystFeedback"]] = relationship(
        "AnalystFeedback", back_populates="analyst"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="generator")

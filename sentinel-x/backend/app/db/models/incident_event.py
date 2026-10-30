"""Incident timeline event model."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSONB_TYPE, Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.incident import Incident
    from app.db.models.user import User


class IncidentEvent(Base, UUIDPrimaryKeyMixin):
    """Timeline entry tracking incident state transitions and analyst actions."""

    __tablename__ = "incident_events"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSONB_TYPE, nullable=True
    )
    actor_id: Mapped[Optional[str]] = mapped_column(
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
    incident: Mapped["Incident"] = relationship("Incident", back_populates="events")
    actor: Mapped[Optional["User"]] = relationship("User", back_populates="incident_events")

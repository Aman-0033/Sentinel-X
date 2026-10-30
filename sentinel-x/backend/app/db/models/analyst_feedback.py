"""Analyst feedback model for detection evaluation and active learning."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.detection import Detection
    from app.db.models.user import User


class AnalystFeedback(Base, UUIDPrimaryKeyMixin):
    """Analyst review feedback on detection accuracy."""

    __tablename__ = "analyst_feedback"
    __table_args__ = (
        CheckConstraint(
            "verdict IN ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'UNCERTAIN')",
            name="ck_analyst_feedback_verdict",
        ),
    )

    detection_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analyst_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    verdict: Mapped[str] = mapped_column(String(30), nullable=False)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    detection: Mapped["Detection"] = relationship("Detection", back_populates="analyst_feedback")
    analyst: Mapped["User"] = relationship("User", back_populates="analyst_feedback")

"""Executive and compliance report generation model."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.incident import Incident
    from app.db.models.user import User


class Report(Base, UUIDPrimaryKeyMixin):
    """Generated compliance and forensic report record."""

    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(
            "format IN ('PDF', 'CSV', 'JSON')",
            name="ck_reports_format",
        ),
        CheckConstraint(
            "status IN ('QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED')",
            name="ck_reports_status",
        ),
    )

    generated_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="QUEUED", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    generator: Mapped["User"] = relationship("User", back_populates="reports")
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="reports")

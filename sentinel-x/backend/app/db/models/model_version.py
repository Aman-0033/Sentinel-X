"""Machine learning model version tracking entity."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSONB_TYPE, Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.detection import Detection
    from app.db.models.user import User


class ModelVersion(Base, UUIDPrimaryKeyMixin):
    """Registered ML model artifact and evaluation metadata."""

    __tablename__ = "model_versions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('TRAINED', 'EVALUATED', 'APPROVED', 'ACTIVE', 'RETIRED')",
            name="ck_model_versions_status",
        ),
        UniqueConstraint("name", "version", name="uq_model_versions_name_version"),
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(50), nullable=False)
    artifact_uri: Mapped[str] = mapped_column(Text, nullable=False)
    feature_schema: Mapped[Dict[str, Any]] = mapped_column(JSONB_TYPE, nullable=False)
    metrics: Mapped[Dict[str, Any]] = mapped_column(JSONB_TYPE, nullable=False)
    checksum: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
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
    creator: Mapped[Optional["User"]] = relationship("User", back_populates="model_versions")
    detections: Mapped[List["Detection"]] = relationship(
        "Detection", back_populates="model_version"
    )

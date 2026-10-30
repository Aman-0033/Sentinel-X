"""Security Audit Logging Service.

Strictly enforces Section 11.12 and Section 36 of architecture.md:
- Records all sensitive operational and administrative actions in the immutable audit trail.
- Applies redaction layer to guarantee no secrets, credentials, or tokens are logged into metadata.
"""

from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.logging import redact_data
from app.db.models.audit_log import AuditLog
from app.repositories.audit_logs import AuditLogRepository


class AuditService:
    """Service handling audit trail emission and sanitization."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repo = AuditLogRepository(db)

    def log_event(
        self,
        action: str,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Create sanitized audit log entry."""
        # Clean and scrub metadata to prevent secret leakage
        sanitized_metadata = redact_data(metadata) if metadata else None

        return self.repo.create(
            action=action.upper().strip(),
            user_id=user_id,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_=sanitized_metadata,
        )

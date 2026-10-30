"""Audit Log Repository.

Data access layer for immutable security audit trail.
"""

from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models.audit_log import AuditLog


class AuditLogRepository:
    """Repository handling database operations for AuditLog records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, log_id: str) -> Optional[AuditLog]:
        """Fetch audit log by primary key ID."""
        return self.db.query(AuditLog).filter(AuditLog.id == log_id).first()

    def create(self, **kwargs) -> AuditLog:
        """Create and persist an immutable audit log entry."""
        log = AuditLog(**kwargs)
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)
        return log

    def list_logs(
        self,
        skip: int = 0,
        limit: int = 50,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[AuditLog]:
        """List audit logs with filtering and pagination."""
        query = self.db.query(AuditLog)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if action:
            query = query.filter(AuditLog.action == action)
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        return query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()

    def count_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> int:
        """Count total matching audit logs."""
        query = self.db.query(AuditLog)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if action:
            query = query.filter(AuditLog.action == action)
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        return query.count()

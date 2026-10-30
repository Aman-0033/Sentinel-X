"""Security Audit Logs REST Endpoints (Section 25 & Section 36)."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import RoleChecker, get_current_user, get_db, get_request_meta
from app.db.models.user import User
from app.repositories.audit_logs import AuditLogRepository
from app.schemas.audit_log import AuditLogItemSchema
from app.schemas.common import ResponseMeta, SuccessResponse

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get(
    "",
    response_model=SuccessResponse[List[AuditLogItemSchema]],
    dependencies=[Depends(RoleChecker(["ADMIN", "ANALYST"]))],
    summary="List security audit logs (ADMIN and ANALYST only)",
)
def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[List[AuditLogItemSchema]]:
    """Retrieve immutable forensic audit records. Access restricted to ADMIN and ANALYST."""
    repo = AuditLogRepository(db)
    logs = repo.list_logs(skip=skip, limit=limit, action=action, resource_type=resource_type)

    data = [
        AuditLogItemSchema(
            id=log.id,
            user_id=log.user_id,
            user_email=log.user.email if log.user else None,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            ip_address=log.ip_address,
            created_at=log.created_at,
            metadata=log.metadata_,
        )
        for log in logs
    ]
    return SuccessResponse(data=data, meta=meta)

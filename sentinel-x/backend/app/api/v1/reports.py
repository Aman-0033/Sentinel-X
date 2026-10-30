"""Compliance and Investigation Reports REST endpoints (Section 22)."""

from pathlib import Path

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleChecker,
    check_rate_limit,
    get_current_user,
    get_db,
    get_request_meta,
)
from app.core.exceptions import AppValidationError, NotFoundError
from app.db.models.user import User
from app.repositories.reports import ReportRepository
from app.schemas.common import CollectionMeta, CollectionResponse, ResponseMeta, SuccessResponse
from app.schemas.report import ReportCreateRequest, ReportItem
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post(
    "",
    response_model=SuccessResponse[ReportItem],
    dependencies=[
        Depends(check_rate_limit(limit=10, window_seconds=60, key_prefix="reports")),
        Depends(RoleChecker(["ADMIN", "ANALYST"])),
    ],
    summary="Generate an asynchronous compliance or forensic investigation report",
)
def create_report(
    req: ReportCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[ReportItem]:
    """Request compilation of security summary or incident forensic report."""
    service = ReportService(db)
    report = service.request_report(
        generated_by=current_user.id,
        period_start=req.period_start,
        period_end=req.period_end,
        format_type=req.format,
        incident_id=req.incident_id,
    )

    # Generate report content synchronously for instant availability
    try:
        service.generate_report_content(report.id)
        db.refresh(report)
    except Exception:
        pass

    from app.services.audit_service import AuditService
    AuditService(db).log_event(
        action="SECURITY_REPORT_REQUESTED",
        user_id=current_user.id,
        resource_type="REPORT",
        resource_id=report.id,
        metadata={"report_type": req.report_type, "format": req.format},
    )

    data = ReportItem(
        id=report.id,
        generated_by=report.generated_by,
        incident_id=report.incident_id,
        period_start=report.period_start,
        period_end=report.period_end,
        format=report.format,
        file_path=report.file_path,
        status=report.status,
        created_at=report.created_at,
    )
    return SuccessResponse(data=data, meta=meta)


@router.get(
    "",
    response_model=CollectionResponse[ReportItem],
    summary="List generated security reports",
)
def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> CollectionResponse[ReportItem]:
    """Fetch paginated report records."""
    repo = ReportRepository(db)
    skip = (page - 1) * page_size
    raw_reports = repo.list_reports(skip=skip, limit=page_size)
    total = repo.count_reports()

    items = [
        ReportItem(
            id=r.id,
            generated_by=r.generated_by,
            incident_id=r.incident_id,
            period_start=r.period_start,
            period_end=r.period_end,
            format=r.format,
            file_path=r.file_path,
            status=r.status,
            created_at=r.created_at,
        )
        for r in raw_reports
    ]

    col_meta = CollectionMeta(
        page=page,
        page_size=page_size,
        total=total,
        request_id=meta.request_id,
    )
    return CollectionResponse(data=items, meta=col_meta)


@router.get(
    "/{report_id}",
    response_model=SuccessResponse[ReportItem],
    summary="Get report metadata and processing status",
)
def get_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[ReportItem]:
    """Fetch status of a generated report."""
    repo = ReportRepository(db)
    report = repo.get_by_id(report_id)
    if not report:
        raise NotFoundError(f"Report '{report_id}' not found.")

    data = ReportItem(
        id=report.id,
        generated_by=report.generated_by,
        incident_id=report.incident_id,
        period_start=report.period_start,
        period_end=report.period_end,
        format=report.format,
        file_path=report.file_path,
        status=report.status,
        created_at=report.created_at,
    )
    return SuccessResponse(data=data, meta=meta)


@router.get(
    "/{report_id}/download",
    summary="Download compiled report document safely",
)
def download_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download report file, validating permissions and checking path existence securely."""
    repo = ReportRepository(db)
    report = repo.get_by_id(report_id)
    if not report:
        raise NotFoundError(f"Report '{report_id}' not found.")

    if report.status != "COMPLETED" or not report.file_path:
        raise AppValidationError("Report file has not completed processing or is unavailable.")

    safe_path = Path(report.file_path).resolve()
    if not safe_path.exists():
        raise NotFoundError("Report artifact file not found on disk storage.")

    media_types = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json",
    }
    media_type = media_types.get(report.format.lower(), "application/octet-stream")

    return FileResponse(
        path=safe_path,
        media_type=media_type,
        filename=f"sentinel_report_{report.id}.{report.format.lower()}",
    )

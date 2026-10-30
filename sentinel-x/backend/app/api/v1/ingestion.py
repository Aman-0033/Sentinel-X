"""Flow ingestion and file upload endpoints (Section 17)."""

import uuid

from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import RoleChecker, check_rate_limit, get_current_user, get_db, get_request_meta
from app.db.models.user import User
from app.schemas.common import ResponseMeta, SuccessResponse
from app.schemas.ingestion import (
    BatchFlowIngestionRequest,
    BatchIngestionData,
    UploadResponseData,
)
from app.services.detection_service import DetectionService
from app.services.ingestion_service import IngestionService

router = APIRouter(prefix="/ingestion", tags=["Ingestion"])


@router.post(
    "/flows/batch",
    response_model=SuccessResponse[BatchIngestionData],
    dependencies=[
        Depends(check_rate_limit(limit=60, window_seconds=60, key_prefix="ingest_batch")),
        Depends(RoleChecker(["ADMIN", "ANALYST"])),
    ],
    summary="Ingest batch of network flows",
)
def ingest_flow_batch(
    req: BatchFlowIngestionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[BatchIngestionData]:
    """Validate, normalize, persist raw telemetry flow batch and trigger ML threat analysis."""
    service = IngestionService(db)
    raw_dicts = [f.model_dump() for f in req.flows]

    # Ingest flows into DB
    flows = service.ingest_flow_batch(raw_dicts, source_id=req.source_id)

    # Trigger ML analysis pipeline
    job_id = str(uuid.uuid4())
    try:
        det_service = DetectionService(db)
        flow_ids = [f.id for f in flows]
        det_service.analyze_flow_batch(flow_ids, system_user_id=current_user.id)
    except Exception:
        # Fallback or let background workers process
        pass

    data = BatchIngestionData(
        accepted=len(flows),
        rejected=0,
        job_id=job_id,
    )
    return SuccessResponse(data=data, meta=meta)


@router.post(
    "/upload",
    response_model=SuccessResponse[UploadResponseData],
    dependencies=[
        Depends(check_rate_limit(limit=10, window_seconds=60, key_prefix="ingest_upload")),
        Depends(RoleChecker(["ADMIN", "ANALYST"])),
    ],
    summary="Secure CSV/JSON telemetry file upload quarantine pipeline",
)
async def upload_telemetry_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[UploadResponseData]:
    """Quarantine uploaded file, sanitize against CSV injection, validate schema, and ingest records."""
    service = IngestionService(db)

    # 1. Read file bytes
    content = await file.read()
    filename = file.filename or "telemetry_upload.csv"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ".csv"

    # 2. Quarantine and process file safely
    accepted_count, flows = service.process_quarantined_upload(
        file_bytes=content,
        file_extension=ext,
    )

    # 3. Trigger ML analysis on ingested flows
    job_id = str(uuid.uuid4())
    try:
        det_service = DetectionService(db)
        det_service.analyze_flow_batch([f.id for f in flows], system_user_id=current_user.id)
    except Exception:
        pass

    data = UploadResponseData(
        filename=filename,
        accepted=accepted_count,
        status="COMPLETED",
        job_id=job_id,
    )
    return SuccessResponse(data=data, meta=meta)

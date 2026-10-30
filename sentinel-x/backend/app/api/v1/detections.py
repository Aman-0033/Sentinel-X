"""Intrusion Detection REST endpoints (Section 18)."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleChecker,
    check_rate_limit,
    get_current_user,
    get_db,
    get_request_meta,
)
from app.core.exceptions import NotFoundError
from app.db.models.user import User
from app.repositories.detections import AnalystFeedbackRepository, DetectionRepository
from app.schemas.common import CollectionMeta, CollectionResponse, ResponseMeta, SuccessResponse
from app.schemas.detection import (
    AnalystFeedbackRequest,
    AnalystFeedbackResponse,
    DetectionAnalyzeData,
    DetectionAnalyzeRequest,
    DetectionDetailData,
    DetectionFlowSummary,
    DetectionItem,
)
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/detections", tags=["Detections"])


@router.post(
    "/analyze",
    response_model=SuccessResponse[DetectionAnalyzeData],
    dependencies=[
        Depends(check_rate_limit(limit=30, window_seconds=60, key_prefix="analyze_flow")),
        Depends(RoleChecker(["ADMIN", "ANALYST"])),
    ],
    summary="Trigger ML threat and anomaly analysis on a flow",
)
def analyze_flow_endpoint(
    req: DetectionAnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[DetectionAnalyzeData]:
    """Execute active ML model inference, SHAP explanation, and risk scoring for an ingested flow."""
    service = DetectionService(db)
    detection = service.analyze_flow(flow_id=req.flow_id, system_user_id=current_user.id)

    data = DetectionAnalyzeData(
        detection_id=detection.id,
        attack_type=detection.attack_type,
        confidence=float(detection.confidence),
        anomaly_score=float(detection.anomaly_score)
        if detection.anomaly_score is not None
        else None,
        risk_score=float(detection.risk_score),
        severity=detection.severity,
    )
    return SuccessResponse(data=data, meta=meta)


@router.get(
    "",
    response_model=CollectionResponse[DetectionItem],
    summary="List detected security threats with filtering and pagination",
)
def list_detections(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    attack_type: Optional[str] = Query(None, description="Filter by attack type"),
    from_time: Optional[datetime] = Query(None, alias="from"),
    to_time: Optional[datetime] = Query(None, alias="to"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> CollectionResponse[DetectionItem]:
    """Fetch paginated security detections with strict upper bounds."""
    repo = DetectionRepository(db)
    skip = (page - 1) * page_size

    items_raw = repo.list_detections(
        skip=skip,
        limit=page_size,
        severity=severity,
        attack_type=attack_type,
        start_time=from_time,
        end_time=to_time,
    )
    total = repo.count_detections(
        severity=severity,
        attack_type=attack_type,
        start_time=from_time,
        end_time=to_time,
    )

    items = []
    for d in items_raw:
        flow_summary = None
        if d.flow:
            flow_summary = DetectionFlowSummary(
                id=d.flow.id,
                source_ip=d.flow.source_ip,
                destination_ip=d.flow.destination_ip,
                source_port=d.flow.source_port,
                destination_port=d.flow.destination_port,
                protocol=d.flow.protocol,
                packets=d.flow.packets,
                bytes=d.flow.bytes,
                duration_ms=d.flow.duration_ms,
            )

        items.append(
            DetectionItem(
                id=d.id,
                flow_id=d.flow_id,
                model_version_id=d.model_version_id,
                attack_type=d.attack_type,
                confidence=float(d.confidence),
                anomaly_score=float(d.anomaly_score) if d.anomaly_score is not None else None,
                risk_score=float(d.risk_score),
                severity=d.severity,
                is_anomaly=d.is_anomaly,
                explanation=d.explanation,
                detected_at=d.detected_at,
                flow=flow_summary,
            )
        )

    col_meta = CollectionMeta(
        page=page,
        page_size=page_size,
        total=total,
        request_id=meta.request_id,
    )
    return CollectionResponse(data=items, meta=col_meta)


@router.get(
    "/{detection_id}",
    response_model=SuccessResponse[DetectionDetailData],
    summary="Get detailed investigation telemetry for a single detection",
)
def get_detection(
    detection_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[DetectionDetailData]:
    """Retrieve detection, flow metrics, SHAP factors, and analyst feedback."""
    repo = DetectionRepository(db)
    d = repo.get_by_id(detection_id)
    if not d:
        raise NotFoundError(f"Detection '{detection_id}' not found.")

    flow_summary = None
    if d.flow:
        flow_summary = DetectionFlowSummary(
            id=d.flow.id,
            source_ip=d.flow.source_ip,
            destination_ip=d.flow.destination_ip,
            source_port=d.flow.source_port,
            destination_port=d.flow.destination_port,
            protocol=d.flow.protocol,
            packets=d.flow.packets,
            bytes=d.flow.bytes,
            duration_ms=d.flow.duration_ms,
        )

    fb_repo = AnalystFeedbackRepository(db)
    feedback_raw = fb_repo.list_for_detection(d.id)
    feedback_items = [
        AnalystFeedbackResponse(
            id=fb.id,
            detection_id=fb.detection_id,
            analyst_id=fb.analyst_id,
            verdict=fb.verdict,
            comment=fb.comment,
            created_at=fb.created_at,
        )
        for fb in feedback_raw
    ]

    data = DetectionDetailData(
        id=d.id,
        flow_id=d.flow_id,
        model_version_id=d.model_version_id,
        attack_type=d.attack_type,
        confidence=float(d.confidence),
        anomaly_score=float(d.anomaly_score) if d.anomaly_score is not None else None,
        risk_score=float(d.risk_score),
        severity=d.severity,
        is_anomaly=d.is_anomaly,
        explanation=d.explanation,
        detected_at=d.detected_at,
        flow=flow_summary,
        feedback=feedback_items,
    )
    return SuccessResponse(data=data, meta=meta)


@router.post(
    "/{detection_id}/feedback",
    response_model=SuccessResponse[AnalystFeedbackResponse],
    dependencies=[Depends(RoleChecker(["ADMIN", "ANALYST"]))],
    summary="Submit analyst triage feedback for a detection",
)
def submit_feedback(
    detection_id: str,
    req: AnalystFeedbackRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[AnalystFeedbackResponse]:
    """Record verified verdict (TRUE_POSITIVE, FALSE_POSITIVE, UNCERTAIN) by an analyst."""
    det_repo = DetectionRepository(db)
    detection = det_repo.get_by_id(detection_id)
    if not detection:
        raise NotFoundError(f"Detection '{detection_id}' not found.")

    fb_repo = AnalystFeedbackRepository(db)
    feedback = fb_repo.create(
        detection_id=detection_id,
        analyst_id=current_user.id,
        verdict=req.verdict,
        comment=req.comment,
    )

    data = AnalystFeedbackResponse(
        id=feedback.id,
        detection_id=feedback.detection_id,
        analyst_id=feedback.analyst_id,
        verdict=feedback.verdict,
        comment=feedback.comment,
        created_at=feedback.created_at,
    )
    return SuccessResponse(data=data, meta=meta)

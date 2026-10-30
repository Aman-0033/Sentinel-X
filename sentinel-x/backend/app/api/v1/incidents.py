"""Security Incident REST endpoints (Section 19)."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleChecker,
    get_current_user,
    get_db,
    get_request_meta,
)
from app.core.exceptions import NotFoundError
from app.db.models.user import User
from app.repositories.incidents import IncidentRepository
from app.schemas.common import CollectionMeta, CollectionResponse, ResponseMeta, SuccessResponse
from app.schemas.detection import DetectionFlowSummary, DetectionItem
from app.schemas.incident import (
    IncidentCreateRequest,
    IncidentDetailData,
    IncidentEventCreateRequest,
    IncidentEventResponse,
    IncidentItem,
    IncidentUpdateRequest,
)
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get(
    "",
    response_model=CollectionResponse[IncidentItem],
    summary="List security incidents with filtering and pagination",
)
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> CollectionResponse[IncidentItem]:
    """Fetch paginated incidents with status, severity, and assignee filters."""
    repo = IncidentRepository(db)
    skip = (page - 1) * page_size

    incidents_raw = repo.list_incidents(
        skip=skip,
        limit=page_size,
        status=status,
        severity=severity,
        assigned_to=assigned_to,
    )
    total = repo.count_incidents(
        status=status,
        severity=severity,
        assigned_to=assigned_to,
    )

    items = [
        IncidentItem(
            id=inc.id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            status=inc.status,
            assigned_to=inc.assigned_to,
            created_by=inc.created_by,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            resolved_at=inc.resolved_at,
            detection_count=len(inc.detections),
        )
        for inc in incidents_raw
    ]

    col_meta = CollectionMeta(
        page=page,
        page_size=page_size,
        total=total,
        request_id=meta.request_id,
    )
    return CollectionResponse(data=items, meta=col_meta)


@router.post(
    "",
    response_model=SuccessResponse[IncidentDetailData],
    dependencies=[Depends(RoleChecker(["ADMIN", "ANALYST"]))],
    summary="Create a new security incident manually",
)
def create_incident(
    req: IncidentCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[IncidentDetailData]:
    """Manually initiate an incident and optionally associate existing detections."""
    repo = IncidentRepository(db)
    incident = repo.create(
        title=req.title,
        description=req.description,
        severity=req.severity,
        status="OPEN",
        created_by=current_user.id,
    )

    # Attach initial detections
    for det_id in req.detection_ids:
        repo.link_detection(incident.id, det_id)

    # Add initial event
    repo.add_event(
        incident_id=incident.id,
        event_type="INCIDENT_CREATED",
        message=f"Incident manually created by {current_user.full_name}.",
        actor_id=current_user.id,
    )

    return get_incident(incident.id, current_user, db, meta)


@router.get(
    "/{incident_id}",
    response_model=SuccessResponse[IncidentDetailData],
    summary="Get full incident investigation details and timeline",
)
def get_incident(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[IncidentDetailData]:
    """Fetch incident record with all attached detections and historical timeline events."""
    repo = IncidentRepository(db)
    inc = repo.get_by_id(incident_id)
    if not inc:
        raise NotFoundError(f"Incident '{incident_id}' not found.")

    detections = []
    for d in inc.detections:
        flow_sum = None
        if d.flow:
            flow_sum = DetectionFlowSummary(
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

        detections.append(
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
                flow=flow_sum,
            )
        )

    events = [
        IncidentEventResponse(
            id=ev.id,
            incident_id=ev.incident_id,
            event_type=ev.event_type,
            message=ev.message,
            metadata=ev.metadata_,
            actor_id=ev.actor_id,
            created_at=ev.created_at,
        )
        for ev in inc.events
    ]

    data = IncidentDetailData(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        assigned_to=inc.assigned_to,
        created_by=inc.created_by,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        resolved_at=inc.resolved_at,
        detection_count=len(detections),
        detections=detections,
        events=events,
    )
    return SuccessResponse(data=data, meta=meta)


@router.patch(
    "/{incident_id}",
    response_model=SuccessResponse[IncidentDetailData],
    dependencies=[Depends(RoleChecker(["ADMIN", "ANALYST"]))],
    summary="Update incident status or assignee",
)
def update_incident(
    incident_id: str,
    req: IncidentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[IncidentDetailData]:
    """Modify incident status or assignee and write timeline entries."""
    service = IncidentService(db)

    if req.status:
        service.update_status(
            incident_id=incident_id,
            new_status=req.status,
            actor_id=current_user.id,
            comment=req.description,
        )

        from app.services.audit_service import AuditService
        AuditService(db).log_event(
            action="INCIDENT_STATUS_UPDATED",
            user_id=current_user.id,
            resource_type="INCIDENT",
            resource_id=incident_id,
            metadata={"status": req.status, "notes": req.description},
        )

    if req.assigned_to is not None:
        service.assign_incident(
            incident_id=incident_id,
            analyst_id=req.assigned_to if req.assigned_to else None,
            actor_id=current_user.id,
        )

    return get_incident(incident_id, current_user, db, meta)


@router.post(
    "/{incident_id}/events",
    response_model=SuccessResponse[IncidentEventResponse],
    dependencies=[Depends(RoleChecker(["ADMIN", "ANALYST"]))],
    summary="Add an analyst note or milestone to an incident",
)
def add_incident_event(
    incident_id: str,
    req: IncidentEventCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[IncidentEventResponse]:
    """Append a timeline event or note to the incident."""
    repo = IncidentRepository(db)
    inc = repo.get_by_id(incident_id)
    if not inc:
        raise NotFoundError(f"Incident '{incident_id}' not found.")

    event = repo.add_event(
        incident_id=incident_id,
        event_type=req.event_type,
        message=req.message,
        actor_id=current_user.id,
        metadata=req.metadata,
    )

    data = IncidentEventResponse(
        id=event.id,
        incident_id=event.incident_id,
        event_type=event.event_type,
        message=event.message,
        metadata=event.metadata_,
        actor_id=event.actor_id,
        created_at=event.created_at,
    )
    return SuccessResponse(data=data, meta=meta)

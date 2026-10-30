"""SOC Dashboard REST endpoints (Section 16)."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, get_request_meta
from app.db.models.detection import Detection
from app.db.models.incident import Incident
from app.db.models.network_flow import NetworkFlow
from app.db.models.user import User
from app.schemas.common import ResponseMeta, SuccessResponse
from app.schemas.dashboard import (
    AttackDistributionItem,
    DashboardSummaryData,
    TopSourceItem,
    TrendPoint,
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/summary",
    response_model=SuccessResponse[DashboardSummaryData],
    summary="Fetch high-level SOC dashboard KPI summary",
)
def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[DashboardSummaryData]:
    """Return active threats, critical counts, open incidents, traffic volume, and calculated security score."""
    # Active threats: non-benign detections in last 24h
    one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)

    active_threats = (
        db.query(Detection)
        .filter(
            Detection.attack_type != "Benign",
            Detection.detected_at >= one_day_ago,
        )
        .count()
    )

    critical_threats = (
        db.query(Detection)
        .filter(
            Detection.severity == "CRITICAL",
            Detection.detected_at >= one_day_ago,
        )
        .count()
    )

    open_incidents = (
        db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()
    )

    traffic_volume = db.query(NetworkFlow).count()

    # Dynamic security score calculation (starts at 100, drops with open threats and incidents)
    penalties = (critical_threats * 10) + (open_incidents * 5) + (active_threats * 2)
    security_score = max(15, min(100, 100 - penalties))

    data = DashboardSummaryData(
        active_threats=active_threats,
        critical_threats=critical_threats,
        open_incidents=open_incidents,
        traffic_volume=traffic_volume,
        security_score=security_score,
    )
    return SuccessResponse(data=data, meta=meta)


@router.get(
    "/trends",
    response_model=SuccessResponse[List[TrendPoint]],
    summary="Fetch threat trend time series",
)
def get_dashboard_trends(
    from_time: Optional[datetime] = Query(None, alias="from"),
    to_time: Optional[datetime] = Query(None, alias="to"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[List[TrendPoint]]:
    """Return historical threat timeline counts grouped by date/hour."""
    end = to_time or datetime.now(timezone.utc)
    start = from_time or (end - timedelta(days=7))

    # Query detections within range
    query = (
        db.query(
            func.date(Detection.detected_at).label("dt"),
            Detection.severity,
            Detection.attack_type,
            func.count(Detection.id).label("cnt"),
        )
        .filter(Detection.detected_at >= start, Detection.detected_at <= end)
        .group_by("dt", Detection.severity, Detection.attack_type)
        .order_by("dt")
    )

    points = []
    for row in query.all():
        points.append(
            TrendPoint(
                timestamp=str(row.dt),
                count=row.cnt,
                severity=row.severity,
                attack_type=row.attack_type,
            )
        )

    return SuccessResponse(data=points, meta=meta)


@router.get(
    "/attack-distribution",
    response_model=SuccessResponse[List[AttackDistributionItem]],
    summary="Fetch attack distribution grouped by category",
)
def get_attack_distribution(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[List[AttackDistributionItem]]:
    """Return distribution of detected attack classes with percentage breakdown."""
    total_threats = db.query(Detection).filter(Detection.attack_type != "Benign").count()

    results = (
        db.query(Detection.attack_type, func.count(Detection.id).label("cnt"))
        .filter(Detection.attack_type != "Benign")
        .group_by(Detection.attack_type)
        .all()
    )

    items = []
    for r in results:
        pct = round((r.cnt / total_threats * 100.0), 1) if total_threats > 0 else 0.0
        items.append(
            AttackDistributionItem(
                attack_type=r.attack_type,
                count=r.cnt,
                percentage=pct,
            )
        )

    return SuccessResponse(data=items, meta=meta)


@router.get(
    "/top-sources",
    response_model=SuccessResponse[List[TopSourceItem]],
    summary="Fetch top suspicious source IP addresses",
)
def get_top_sources(
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[List[TopSourceItem]]:
    """Return source IPs ranked by malicious activity and risk level."""
    results = (
        db.query(
            NetworkFlow.source_ip,
            func.count(Detection.id).label("attack_count"),
            func.max(Detection.risk_score).label("max_risk"),
        )
        .join(Detection, Detection.flow_id == NetworkFlow.id)
        .filter(Detection.attack_type != "Benign")
        .group_by(NetworkFlow.source_ip)
        .order_by(func.count(Detection.id).desc())
        .limit(limit)
        .all()
    )

    items = []
    for r in results:
        risk_val = float(r.max_risk or 0.0)
        sev = "CRITICAL" if risk_val >= 90 else "HIGH" if risk_val >= 70 else "MEDIUM"
        items.append(
            TopSourceItem(
                source_ip=r.source_ip,
                attack_count=r.attack_count,
                max_severity=sev,
                max_risk_score=risk_val,
            )
        )

    return SuccessResponse(data=items, meta=meta)

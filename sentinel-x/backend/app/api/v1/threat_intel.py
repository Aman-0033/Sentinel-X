"""Threat Intelligence REST endpoints (Section 20)."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import (
    check_rate_limit,
    get_current_user,
    get_db,
    get_request_meta,
)
from app.db.models.user import User
from app.schemas.common import ResponseMeta, SuccessResponse
from app.schemas.threat_intel import ThreatIntelData, ThreatIntelEnrichRequest
from app.services.threat_intel_service import ThreatIntelService
from app.threat_intel.allowlist import validate_threat_intel_indicator

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get(
    "/ip/{ip}",
    response_model=SuccessResponse[ThreatIntelData],
    dependencies=[Depends(check_rate_limit(limit=30, window_seconds=60, key_prefix="ti_ip"))],
    summary="Query threat intelligence reputation for an IP address",
)
async def query_ip_threat_intel(
    ip: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[ThreatIntelData]:
    """Validate IP address strictly against private address ranges and fetch external intelligence."""
    clean_ip = validate_threat_intel_indicator(ip, "ip")
    service = ThreatIntelService(db)
    result = await service.enrich_ip(clean_ip)

    data = ThreatIntelData(
        indicator=result.indicator,
        indicator_type=result.indicator_type,
        provider=result.provider,
        reputation_score=result.reputation_score,
        verdict=result.verdict,
        country=result.country,
        asn=result.asn,
        checked_at=result.checked_at,
        response_data=result.response_data,
        error=result.error,
    )
    return SuccessResponse(data=data, meta=meta)


@router.post(
    "/enrich",
    response_model=SuccessResponse[ThreatIntelData],
    dependencies=[Depends(check_rate_limit(limit=20, window_seconds=60, key_prefix="ti_enrich"))],
    summary="Enrich an IP, domain, or hash indicator",
)
async def enrich_indicator_endpoint(
    req: ThreatIntelEnrichRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[ThreatIntelData]:
    """Validate and enrich indicator using approved provider allowlist."""
    service = ThreatIntelService(db)
    result = await service.enrich_indicator(
        indicator=req.indicator_value,
        indicator_type=req.indicator_type,
        provider=req.provider or "virustotal",
    )

    data = ThreatIntelData(
        indicator=result.indicator,
        indicator_type=result.indicator_type,
        provider=result.provider,
        reputation_score=result.reputation_score,
        verdict=result.verdict,
        country=result.country,
        asn=result.asn,
        checked_at=result.checked_at,
        response_data=result.response_data,
        error=result.error,
    )
    return SuccessResponse(data=data, meta=meta)

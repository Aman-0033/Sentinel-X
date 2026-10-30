"""Threat Intelligence Orchestrator Service (Section 8).

Coordinates multiple threat intelligence providers, database caching,
and failure-tolerant enrichment.
"""

from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.repositories.threat_intel import ThreatIntelRepository
from app.threat_intel.abuseipdb import AbuseIPDBProvider
from app.threat_intel.allowlist import validate_provider_name, validate_threat_intel_indicator
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult
from app.threat_intel.virustotal import VirusTotalProvider


class ThreatIntelOrchestrator:
    """Manages provider lookups, caching, and fallback policies."""

    def __init__(self, providers: Optional[Dict[str, ThreatIntelProvider]] = None):
        self.providers: Dict[str, ThreatIntelProvider] = providers or {
            "virustotal": VirusTotalProvider(),
            "abuseipdb": AbuseIPDBProvider(),
        }

    def register_provider(self, provider: ThreatIntelProvider) -> None:
        """Register a custom or test threat intelligence provider."""
        self.providers[provider.provider_name] = provider

    async def enrich_indicator(
        self,
        indicator: str,
        indicator_type: str = "ip",
        preferred_provider: str = "virustotal",
        db: Optional[Session] = None,
        detection_id: Optional[str] = None,
    ) -> ThreatIntelResult:
        """Enrich indicator with cache checking and graceful provider fallback."""
        clean_indicator = validate_threat_intel_indicator(indicator, indicator_type)
        provider_name = validate_provider_name(preferred_provider)

        # 1. Check database cache if DB session available
        if db is not None:
            repo = ThreatIntelRepository(db)
            now = datetime.now(timezone.utc)
            cached = repo.get_active_by_indicator(clean_indicator, provider_name)
            if cached and (cached.expires_at is None or cached.expires_at > now):
                return ThreatIntelResult(
                    indicator=cached.indicator_value,
                    indicator_type=cached.indicator_type,
                    provider=cached.provider,
                    reputation_score=float(cached.reputation_score)
                    if cached.reputation_score is not None
                    else None,
                    verdict=cached.verdict,
                    country=cached.country,
                    asn=cached.asn,
                    response_data=cached.response_data,
                    checked_at=cached.checked_at,
                    expires_at=cached.expires_at,
                )

        # 2. Select Provider
        provider = self.providers.get(provider_name) or self.providers.get("virustotal")
        if not provider:
            now = datetime.now(timezone.utc)
            return ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider=provider_name,
                reputation_score=None,
                verdict="UNKNOWN",
                country=None,
                asn=None,
                response_data=None,
                checked_at=now,
                error="NO_PROVIDER_AVAILABLE",
            )

        # 3. Query external provider
        result = await provider.check_indicator(clean_indicator, indicator_type)

        # 4. Cache result to database if DB session and detection_id provided
        if db is not None and detection_id:
            try:
                repo = ThreatIntelRepository(db)
                repo.create(
                    detection_id=detection_id,
                    indicator_type=result.indicator_type,
                    indicator_value=result.indicator,
                    provider=result.provider,
                    reputation_score=result.reputation_score,
                    verdict=result.verdict,
                    country=result.country,
                    asn=result.asn,
                    response_data=result.response_data,
                    checked_at=result.checked_at,
                    expires_at=result.expires_at,
                )
            except Exception:
                # Do not fail overall request if cache write encounters conflict
                pass

        return result

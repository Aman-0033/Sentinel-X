"""AbuseIPDB Threat Intelligence Provider Integration (Section 8)."""

from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.core.config import get_settings
from app.threat_intel.allowlist import APPROVED_BASE_URLS, validate_threat_intel_indicator
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult
from app.threat_intel.response_validator import validate_http_response


class AbuseIPDBProvider(ThreatIntelProvider):
    """Enriches IP indicators via the AbuseIPDB v2 API with timeout and safe fallback."""

    def __init__(self, api_key: Optional[str] = None, timeout_seconds: float = 4.0):
        try:
            settings = get_settings()
            self.api_key = api_key or getattr(settings, "ABUSEIPDB_API_KEY", None)
        except Exception:
            self.api_key = api_key
        self.timeout = timeout_seconds
        self.base_url = APPROVED_BASE_URLS["abuseipdb"]

    @property
    def provider_name(self) -> str:
        return "abuseipdb"

    async def check_indicator(
        self, indicator: str, indicator_type: str = "ip"
    ) -> ThreatIntelResult:
        """Query AbuseIPDB API for the given IP address."""
        now = datetime.now(timezone.utc)
        clean_indicator = validate_threat_intel_indicator(indicator, indicator_type)

        if indicator_type != "ip":
            return ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider=self.provider_name,
                reputation_score=None,
                verdict="UNKNOWN",
                country=None,
                asn=None,
                response_data={"notice": "AbuseIPDB only supports IP indicators."},
                checked_at=now,
                error="UNSUPPORTED_INDICATOR_TYPE",
            )

        if not self.api_key or self.api_key in ("placeholder", "mock", ""):
            return ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider=self.provider_name,
                reputation_score=None,
                verdict="UNKNOWN",
                country=None,
                asn=None,
                response_data={
                    "notice": "AbuseIPDB API key not configured. Operating in degraded mode."
                },
                checked_at=now,
                expires_at=now + timedelta(hours=24),
                error="ABUSEIPDB_KEY_UNCONFIGURED",
            )

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Sentinel-X/1.0",
        }
        params = {
            "ipAddress": clean_indicator,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/check", headers=headers, params=params)
                data = validate_http_response(resp, self.provider_name)

            record_data = data.get("data", {})
            abuse_score = float(record_data.get("abuseConfidenceScore", 0))

            if abuse_score >= 50.0:
                verdict = "MALICIOUS"
            elif abuse_score >= 20.0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"

            country = record_data.get("countryCode")

            return ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider=self.provider_name,
                reputation_score=abuse_score,
                verdict=verdict,
                country=str(country)[:5] if country else None,
                asn=None,
                response_data=record_data,
                checked_at=now,
                expires_at=now + timedelta(hours=24),
            )

        except Exception as exc:
            return ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider=self.provider_name,
                reputation_score=None,
                verdict="UNKNOWN",
                country=None,
                asn=None,
                response_data=None,
                checked_at=now,
                error=f"AbuseIPDB lookup failed: {str(exc)}",
            )

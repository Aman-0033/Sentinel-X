"""VirusTotal Threat Intelligence Provider Integration (Section 8)."""

from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.core.config import get_settings
from app.threat_intel.allowlist import APPROVED_BASE_URLS, validate_threat_intel_indicator
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult
from app.threat_intel.response_validator import validate_http_response


class VirusTotalProvider(ThreatIntelProvider):
    """Enriches indicators via the VirusTotal v3 API with timeout and safe fallback."""

    def __init__(self, api_key: Optional[str] = None, timeout_seconds: float = 4.0):
        try:
            settings = get_settings()
            self.api_key = api_key or getattr(settings, "VIRUSTOTAL_API_KEY", None)
        except Exception:
            self.api_key = api_key
        self.timeout = timeout_seconds
        self.base_url = APPROVED_BASE_URLS["virustotal"]

    @property
    def provider_name(self) -> str:
        return "virustotal"

    async def check_indicator(
        self, indicator: str, indicator_type: str = "ip"
    ) -> ThreatIntelResult:
        """Query VirusTotal v3 API for the given indicator."""
        now = datetime.now(timezone.utc)
        clean_indicator = validate_threat_intel_indicator(indicator, indicator_type)

        if not self.api_key or self.api_key in ("placeholder", "mock", ""):
            # Safe degradation when external provider key is not configured (Section 8)
            return ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider=self.provider_name,
                reputation_score=None,
                verdict="UNKNOWN",
                country=None,
                asn=None,
                response_data={
                    "notice": "VirusTotal API key not configured. Operating in degraded mode."
                },
                checked_at=now,
                expires_at=now + timedelta(hours=24),
                error="VIRUSTOTAL_KEY_UNCONFIGURED",
            )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Sentinel-X/1.0",
        }

        # Build endpoint according to indicator type
        if indicator_type == "ip":
            endpoint = f"{self.base_url}/ip_addresses/{clean_indicator}"
        elif indicator_type == "domain":
            endpoint = f"{self.base_url}/domains/{clean_indicator}"
        else:
            endpoint = f"{self.base_url}/files/{clean_indicator}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(endpoint, headers=headers)
                data = validate_http_response(resp, self.provider_name)

            if data.get("not_found"):
                return ThreatIntelResult(
                    indicator=clean_indicator,
                    indicator_type=indicator_type,
                    provider=self.provider_name,
                    reputation_score=0.0,
                    verdict="CLEAN",
                    country=None,
                    asn=None,
                    response_data=data,
                    checked_at=now,
                    expires_at=now + timedelta(hours=24),
                )

            # Parse attributes
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = int(stats.get("malicious", 0))
            suspicious_count = int(stats.get("suspicious", 0))

            # Verdict derivation
            if malicious_count >= 3:
                verdict = "MALICIOUS"
                rep_score = min(100.0, 50.0 + (malicious_count * 5.0))
            elif malicious_count >= 1 or suspicious_count >= 2:
                verdict = "SUSPICIOUS"
                rep_score = 45.0
            else:
                verdict = "CLEAN"
                rep_score = 0.0

            country = attributes.get("country")
            asn = attributes.get("asn")

            return ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider=self.provider_name,
                reputation_score=rep_score,
                verdict=verdict,
                country=str(country)[:5] if country else None,
                asn=int(asn) if asn is not None else None,
                response_data=attributes,
                checked_at=now,
                expires_at=now + timedelta(hours=24),
            )

        except Exception as exc:
            # Never crash application if external provider fails (Section 8)
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
                error=f"VirusTotal lookup failed: {str(exc)}",
            )

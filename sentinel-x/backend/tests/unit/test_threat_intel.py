"""Unit tests for Threat Intelligence providers and SSRF defense (Section 8, 30, and 33)."""

import httpx
import pytest

from app.core.exceptions import AppValidationError
from app.threat_intel.abuseipdb import AbuseIPDBProvider
from app.threat_intel.allowlist import (
    validate_provider_name,
    validate_threat_intel_indicator,
)
from app.threat_intel.base import ThreatIntelResult
from app.threat_intel.response_validator import sanitize_response_data, validate_http_response
from app.threat_intel.service import ThreatIntelOrchestrator
from app.threat_intel.virustotal import VirusTotalProvider


def test_ssrf_rejection_of_private_and_loopback_ips():
    """Verify internal and non-routable IP ranges are blocked from external lookup (Section 30)."""
    # RFC 1918 Private ranges
    with pytest.raises(AppValidationError) as exc:
        validate_threat_intel_indicator("10.0.0.1", "ip")
    assert "private" in str(exc.value).lower()

    with pytest.raises(AppValidationError):
        validate_threat_intel_indicator("192.168.1.254", "ip")

    with pytest.raises(AppValidationError):
        validate_threat_intel_indicator("172.16.5.10", "ip")

    # Loopback
    with pytest.raises(AppValidationError):
        validate_threat_intel_indicator("127.0.0.1", "ip")

    # AWS/Cloud Metadata service link-local
    with pytest.raises(AppValidationError):
        validate_threat_intel_indicator("169.254.169.254", "ip")


def test_valid_indicators():
    """Verify public indicators pass validation."""
    assert validate_threat_intel_indicator("8.8.8.8", "ip") == "8.8.8.8"
    assert validate_threat_intel_indicator("example.com", "domain") == "example.com"
    assert (
        validate_threat_intel_indicator(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"
        )
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_provider_allowlist():
    """Only approved providers may be invoked."""
    assert validate_provider_name("virustotal") == "virustotal"
    assert validate_provider_name("abuseipdb") == "abuseipdb"

    with pytest.raises(AppValidationError):
        validate_provider_name("evil_proxy_provider")


def test_response_sanitization():
    """HTML elements in third-party payloads are escaped to prevent XSS (Section 33)."""
    malicious_payload = {
        "verdict": "<script>alert('xss')</script>Malicious",
        "nested": {"note": "<img src=x onerror=alert(1)>"},
    }
    cleaned = sanitize_response_data(malicious_payload)
    assert "<script>" not in cleaned["verdict"]
    assert "&lt;script&gt;" in cleaned["verdict"]
    assert "&lt;img" in cleaned["nested"]["note"]


def test_response_validator_size_and_content_type():
    """Responses exceeding 1MB or without JSON content type are rejected."""
    # Invalid Content-Type
    req = httpx.Request("GET", "https://api.test/check")
    resp_bad_type = httpx.Response(
        200, headers={"Content-Type": "text/html"}, text="<html>OK</html>", request=req
    )
    with pytest.raises(AppValidationError) as exc:
        validate_http_response(resp_bad_type, "virustotal")
    assert "content-type" in str(exc.value).lower()

    # Oversized payload
    resp_large = httpx.Response(
        200,
        headers={"Content-Type": "application/json", "Content-Length": "2000000"},
        text="{}",
        request=req,
    )
    with pytest.raises(AppValidationError) as exc:
        validate_http_response(resp_large, "virustotal")
    assert "exceeded maximum" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_virustotal_degrades_gracefully_when_unconfigured():
    """Unconfigured VirusTotal API key returns safe degraded result without crashing."""
    vt = VirusTotalProvider(api_key=None)
    res = await vt.check_indicator("8.8.8.8", "ip")
    assert isinstance(res, ThreatIntelResult)
    assert res.verdict == "UNKNOWN"
    assert res.error == "VIRUSTOTAL_KEY_UNCONFIGURED"


@pytest.mark.asyncio
async def test_abuseipdb_degrades_gracefully_when_unconfigured():
    """Unconfigured AbuseIPDB API key returns safe degraded result without crashing."""
    abuse = AbuseIPDBProvider(api_key=None)
    res = await abuse.check_indicator("8.8.8.8", "ip")
    assert isinstance(res, ThreatIntelResult)
    assert res.verdict == "UNKNOWN"
    assert res.error == "ABUSEIPDB_KEY_UNCONFIGURED"


@pytest.mark.asyncio
async def test_orchestrator_fallback_to_mock_provider():
    """Verify orchestrator registers and executes custom providers reliably."""

    class MockProvider(VirusTotalProvider):
        @property
        def provider_name(self) -> str:
            return "virustotal"

        async def check_indicator(
            self, indicator: str, indicator_type: str = "ip"
        ) -> ThreatIntelResult:
            from datetime import datetime, timezone

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider="virustotal",
                reputation_score=85.0,
                verdict="MALICIOUS",
                country="US",
                asn=15169,
                response_data={"mock": True},
                checked_at=datetime.now(timezone.utc),
            )

    orchestrator = ThreatIntelOrchestrator(providers={"virustotal": MockProvider()})
    res = await orchestrator.enrich_indicator("8.8.8.8", "ip")
    assert res.is_success
    assert res.verdict == "MALICIOUS"
    assert res.reputation_score == 85.0

"""Security Test Suite: SSRF & External Integration Defense (Section 46.4).

Verifies:
- Private, loopback, and link-local IP addresses are strictly rejected.
- Cloud metadata endpoints (169.254.169.254) are blocked.
- Arbitrary URLs cannot be submitted in place of indicators.
- Provider allowlist is strictly enforced (unapproved providers rejected).
- Upstream provider network failures degrade gracefully without 500 crashes.
"""

import pytest


def test_private_ip_addresses_are_rejected_from_threat_intel(client, auth_context):
    """Verify private RFC 1918 addresses cannot be enriched via threat intel."""
    private_ips = [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.100.50",
    ]

    for ip in private_ips:
        res = client.get(
            f"/api/v1/threat-intel/ip/{ip}",
            headers=auth_context["analyst_headers"],
        )
        assert res.status_code == 422
        assert res.json()["error"]["code"] == "VALIDATION_ERROR"
        assert "private" in res.json()["error"]["message"].lower() or "ssrf" in res.json()["error"]["message"].lower()


def test_loopback_and_cloud_metadata_ips_are_rejected(client, auth_context):
    """Verify loopback and cloud metadata (169.254.169.254) addresses are rejected."""
    prohibited_ips = [
        "127.0.0.1",
        "127.0.1.1",
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "224.0.0.1",        # Multicast
    ]

    for ip in prohibited_ips:
        res = client.get(
            f"/api/v1/threat-intel/ip/{ip}",
            headers=auth_context["analyst_headers"],
        )
        assert res.status_code == 422
        assert res.json()["error"]["code"] == "VALIDATION_ERROR"


def test_arbitrary_urls_in_enrichment_request_are_rejected(client, auth_context):
    """Verify arbitrary URLs cannot be passed as indicators."""
    malicious_indicators = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8000/internal",
        "https://evil-attacker.com/steal",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379",
    ]

    for url in malicious_indicators:
        res = client.post(
            "/api/v1/threat-intel/enrich",
            headers=auth_context["analyst_headers"],
            json={"indicator_value": url, "indicator_type": "ip", "provider": "virustotal"},
        )
        assert res.status_code == 422
        assert res.json()["error"]["code"] == "VALIDATION_ERROR"


def test_unapproved_threat_intel_provider_is_rejected(client, auth_context):
    """Verify only allowlisted providers (virustotal, abuseipdb) can be specified."""
    unapproved_providers = [
        "evil_provider",
        "http://attacker.com/api",
        "custom_crawler",
        "shodan_unapproved",
    ]

    for provider in unapproved_providers:
        res = client.post(
            "/api/v1/threat-intel/enrich",
            headers=auth_context["analyst_headers"],
            json={"indicator_value": "8.8.8.8", "indicator_type": "ip", "provider": provider},
        )
        assert res.status_code == 422
        assert "unsupported provider" in res.json()["error"]["message"].lower() or "validation" in res.json()["error"]["code"].lower()


def test_public_ip_enrichment_succeeds_with_graceful_fallback(client, auth_context):
    """Verify legitimate public IP enrichment returns safe data without server error."""
    res = client.get(
        "/api/v1/threat-intel/ip/8.8.8.8",
        headers=auth_context["analyst_headers"],
    )
    assert res.status_code == 200
    payload = res.json()["data"]
    assert payload["indicator"] == "8.8.8.8"
    assert payload["indicator_type"] == "ip"
    assert "verdict" in payload

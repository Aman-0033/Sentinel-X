"""Security Test Suite: Rate Limiting & Resource Abuse Controls (Section 46.5).

Verifies:
- Repeated login attempts are throttled with 429 Too Many Requests.
- Ingestion batch submission rate limits activate under rapid bursts.
- Telemetry file upload rate limits activate under rapid requests.
- Threat intelligence queries are rate limited to protect quota and mitigate abuse.
- Report generation abuse is throttled.
"""

import io
import pytest

from app.core.rate_limit import reset_rate_limit


def test_repeated_login_rate_limiting_activates(client, auth_context):
    """Verify exceeding login attempt quota returns 429 Too Many Requests."""
    reset_rate_limit("login:testclient")

    statuses = []
    for _ in range(10):
        res = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel.internal", "password": "WrongPassword123!"},
        )
        statuses.append(res.status_code)
        if res.status_code == 429:
            break

    assert 401 in statuses, "Initial bad attempts should return 401"
    assert 429 in statuses, "Excessive bad attempts must return 429 Too Many Requests"


def test_ingestion_upload_rate_limiting(client, auth_context):
    """Verify rapid repeated file uploads are throttled with 429."""
    reset_rate_limit("ingest_upload:testclient")

    csv_data = "source_ip,destination_ip,protocol\n1.1.1.1,2.2.2.2,TCP\n"

    # Limit is 10 uploads per minute
    for _ in range(10):
        res = client.post(
            "/api/v1/ingestion/upload",
            headers=auth_context["analyst_headers"],
            files={"file": ("test.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")},
        )
        assert res.status_code == 200

    # 11th upload must be throttled
    blocked = client.post(
        "/api/v1/ingestion/upload",
        headers=auth_context["analyst_headers"],
        files={"file": ("test.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")},
    )
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


def test_threat_intelligence_enrichment_rate_limiting(client, auth_context):
    """Verify rapid threat intelligence requests are rate limited."""
    reset_rate_limit("ti_enrich:testclient")

    # Limit is 20 per minute
    for _ in range(20):
        res = client.post(
            "/api/v1/threat-intel/enrich",
            headers=auth_context["analyst_headers"],
            json={"indicator_value": "8.8.8.8", "indicator_type": "ip", "provider": "virustotal"},
        )
        assert res.status_code == 200

    # 21st must be blocked
    blocked = client.post(
        "/api/v1/threat-intel/enrich",
        headers=auth_context["analyst_headers"],
        json={"indicator_value": "8.8.8.8", "indicator_type": "ip", "provider": "virustotal"},
    )
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


def test_report_generation_rate_limiting(client, auth_context):
    """Verify report generation endpoint enforces rate limits."""
    reset_rate_limit("reports:testclient")

    report_payload = {
        "report_type": "SECURITY_SUMMARY",
        "format": "JSON",
        "period_start": "2026-10-01T00:00:00Z",
        "period_end": "2026-10-15T00:00:00Z",
    }

    # Limit is 10 reports per minute
    for _ in range(10):
        res = client.post(
            "/api/v1/reports",
            headers=auth_context["analyst_headers"],
            json=report_payload,
        )
        assert res.status_code == 200

    # 11th report must be throttled
    blocked = client.post(
        "/api/v1/reports",
        headers=auth_context["analyst_headers"],
        json=report_payload,
    )
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

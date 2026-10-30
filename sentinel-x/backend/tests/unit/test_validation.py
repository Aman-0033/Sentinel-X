"""Unit tests for strict input validation functions (Section 39 and Section 40)."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from app.core.exceptions import AppValidationError
from app.core.validation import (
    validate_date_range,
    validate_email,
    validate_incident_status,
    validate_ip_address,
    validate_password,
    validate_port,
    validate_protocol,
    validate_scores,
    validate_search_query,
    validate_severity,
    validate_string,
    validate_uuid,
)


def test_validate_email_success_and_normalization():
    """Verify email normalization and validation."""
    assert validate_email("  ANALYST@Sentinel.Internal  ") == "analyst@sentinel.internal"
    assert validate_email("user.name+tag@domain.co.uk") == "user.name+tag@domain.co.uk"


def test_validate_email_rejection():
    """Verify malformed or oversized emails are rejected."""
    with pytest.raises(AppValidationError):
        validate_email("not-an-email")
    with pytest.raises(AppValidationError):
        validate_email("user@")
    with pytest.raises(AppValidationError):
        validate_email("@domain.com")
    with pytest.raises(AppValidationError):
        validate_email("a" * 250 + "@domain.com")  # Exceeds 255


def test_validate_password_policy():
    """Verify password policy (12-128 chars, reject common breach passwords)."""
    # Valid
    assert (
        validate_password("SuperSecureSentinel2026!Passphrase")
        == "SuperSecureSentinel2026!Passphrase"
    )

    # Too short (<12)
    with pytest.raises(AppValidationError) as exc:
        validate_password("Short12345!")
    assert "at least 12 characters" in str(exc.value)

    # Too long (>128)
    with pytest.raises(AppValidationError) as exc:
        validate_password("a" * 129)
    assert "maximum allowed length" in str(exc.value)

    # Breached / common password
    with pytest.raises(AppValidationError) as exc:
        validate_password("password123456")
    assert "too common" in str(exc.value)


def test_validate_uuid():
    """Verify strict UUID parsing."""
    valid_uuid = "12345678-1234-5678-1234-567812345678"
    assert validate_uuid(valid_uuid) == valid_uuid

    with pytest.raises(AppValidationError):
        validate_uuid("not-a-uuid")
    with pytest.raises(AppValidationError):
        validate_uuid("12345678-1234-5678-1234-56781234567g")


def test_validate_ip_address():
    """Verify IPv4 and IPv6 validation."""
    assert validate_ip_address("192.168.1.1") == "192.168.1.1"
    assert validate_ip_address("10.0.0.254") == "10.0.0.254"
    assert (
        validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        == "2001:db8:85a3::8a2e:370:7334"
    )

    with pytest.raises(AppValidationError):
        validate_ip_address("999.999.999.999")
    with pytest.raises(AppValidationError):
        validate_ip_address("192.168.1.256")
    with pytest.raises(AppValidationError):
        validate_ip_address("invalid_ip")


def test_validate_port():
    """Verify port range 1-65535."""
    assert validate_port(80) == 80
    assert validate_port("443") == 443
    assert validate_port(65535) == 65535

    with pytest.raises(AppValidationError):
        validate_port(0)
    with pytest.raises(AppValidationError):
        validate_port(65536)
    with pytest.raises(AppValidationError):
        validate_port("not_a_port")


def test_validate_protocol():
    """Verify protocol allowlist (TCP, UDP, ICMP)."""
    assert validate_protocol("tcp") == "TCP"
    assert validate_protocol("UDP") == "UDP"
    assert validate_protocol("icmp") == "ICMP"

    with pytest.raises(AppValidationError):
        validate_protocol("HTTP")
    with pytest.raises(AppValidationError):
        validate_protocol("DNS")


def test_validate_severity():
    """Verify severity allowlist (LOW, MEDIUM, HIGH, CRITICAL)."""
    assert validate_severity("critical") == "CRITICAL"
    assert validate_severity("HIGH") == "HIGH"

    with pytest.raises(AppValidationError):
        validate_severity("EXTREME")


def test_validate_incident_status():
    """Verify incident status allowlist."""
    assert validate_incident_status("open") == "OPEN"
    assert validate_incident_status("INVESTIGATING") == "INVESTIGATING"

    with pytest.raises(AppValidationError):
        validate_incident_status("PENDING")


def test_validate_search_query_sqli_detection():
    """Verify search query protects against SQL injection signatures."""
    assert validate_search_query("192.168.1.100") == "192.168.1.100"
    assert validate_search_query("SYN_Flood") == "SYN_Flood"

    with pytest.raises(AppValidationError):
        validate_search_query("' OR 1=1 --")
    with pytest.raises(AppValidationError):
        validate_search_query("admin; DROP TABLE users;")
    with pytest.raises(AppValidationError):
        validate_search_query("UNION SELECT * FROM audit_logs")


def test_validate_date_range():
    """Verify ISO-8601 UTC date range checks."""
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(days=10)

    start, end = validate_date_range(earlier.isoformat(), now.isoformat())
    assert start <= end

    # start > end
    with pytest.raises(AppValidationError):
        validate_date_range(now.isoformat(), earlier.isoformat())

    # range > max_days (90)
    old = now - timedelta(days=120)
    with pytest.raises(AppValidationError):
        validate_date_range(old.isoformat(), now.isoformat(), max_days=90)


def test_validate_scores():
    """Verify confidence and risk score limits."""
    validate_scores(confidence=0.5, risk_score=85.0)
    validate_scores(confidence=Decimal("1.0"), risk_score=Decimal("100.0"))

    with pytest.raises(AppValidationError):
        validate_scores(confidence=1.05)

    with pytest.raises(AppValidationError):
        validate_scores(confidence=-0.1)

    with pytest.raises(AppValidationError):
        validate_scores(risk_score=100.5)

    with pytest.raises(AppValidationError):
        validate_scores(risk_score=-5.0)


def test_validate_string():
    """Verify string bounds and control character sanitization."""
    assert validate_string("Safe text", min_length=2, max_length=50) == "Safe text"

    with pytest.raises(AppValidationError):
        validate_string("a", min_length=3)

    with pytest.raises(AppValidationError):
        validate_string("a" * 300, max_length=100)

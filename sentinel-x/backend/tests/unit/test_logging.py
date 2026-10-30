"""Unit tests for structured JSON logging and sensitive data redaction."""

import json
import logging

from app.core.logging import StructuredJsonFormatter, redact_data, redact_string, request_id_ctx


def test_redact_sensitive_keys_in_dictionary():
    """Verify dictionary keys containing sensitive keywords are replaced with [REDACTED]."""
    payload = {
        "username": "analyst@sentinel.internal",
        "password": "super_secret_password_123",
        "nested": {
            "jwt_secret": "secret_key_value",
            "access_token": "ey1234567890",
            "safe_metric": 42,
        },
        "api_key": "VT_12345",
        "headers": {
            "Authorization": "Bearer some_token",
        },
    }
    redacted = redact_data(payload)
    assert redacted["username"] == "analyst@sentinel.internal"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["nested"]["jwt_secret"] == "[REDACTED]"
    assert redacted["nested"]["access_token"] == "[REDACTED]"
    assert redacted["nested"]["safe_metric"] == 42
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["headers"]["Authorization"] == "[REDACTED]"


def test_redact_bearer_token_in_message_string():
    """Verify Bearer tokens embedded in log strings are scrubbed."""
    msg = "User authenticated with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc12345"
    sanitized = redact_string(msg)
    assert "Bearer [REDACTED_JWT]" in sanitized
    assert "eyJhbGci" not in sanitized


def test_redact_database_url_credentials_in_message():
    """Verify DB passwords embedded in connection strings are scrubbed."""
    msg = "Connecting to postgresql://sentinel:super_secret_pass@db.internal:5432/sentinel_x"
    sanitized = redact_string(msg)
    assert "super_secret_pass" not in sanitized
    assert "postgresql://sentinel:[REDACTED]@db.internal:5432/sentinel_x" in sanitized


def test_structured_json_formatter_output():
    """Verify StructuredJsonFormatter outputs valid, parseable JSON with all required fields."""
    formatter = StructuredJsonFormatter()
    record = logging.LogRecord(
        name="sentinel.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Threat detection processed for IP 192.168.1.50",
        args=(),
        exc_info=None,
    )
    record.request_id = "req-12345-abcde"
    record.user_id = "user-999"
    record.action = "threat_scan"
    record.resource = "flow_123"

    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "sentinel.test"
    assert parsed["message"] == "Threat detection processed for IP 192.168.1.50"
    assert parsed["request_id"] == "req-12345-abcde"
    assert parsed["user_id"] == "user-999"
    assert parsed["action"] == "threat_scan"
    assert parsed["resource"] == "flow_123"
    assert "timestamp" in parsed


def test_request_id_from_contextvar():
    """Verify formatter automatically picks up request_id from contextvar."""
    token = request_id_ctx.set("ctx-request-id-789")
    try:
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="sentinel.ctx",
            level=logging.WARNING,
            pathname="test.py",
            lineno=20,
            msg="Anomaly score exceeded threshold",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["request_id"] == "ctx-request-id-789"
    finally:
        request_id_ctx.reset(token)

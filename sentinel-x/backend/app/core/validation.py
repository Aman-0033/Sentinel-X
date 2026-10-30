"""Strict Input Validation and Sanitization Module.

Implements Section 39 and Section 40 of architecture.md:
Validates and normalizes all incoming values at the trust boundary before processing.
"""

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional, Tuple

from app.core.exceptions import AppValidationError

# Security Allowlist Constants
ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP"}
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_INCIDENT_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}
ALLOWED_SOURCE_TYPES = {"DATASET", "CSV_UPLOAD", "JSON_UPLOAD", "SIMULATOR", "LIVE_COLLECTOR"}
ALLOWED_FEEDBACK_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}
ALLOWED_REPORT_FORMATS = {"PDF", "CSV", "JSON"}
ALLOWED_REPORT_STATUSES = {"QUEUED", "PROCESSING", "COMPLETED", "FAILED"}

# Common/Breached Password Blacklist (Section 24.4)
BREACHED_PASSWORDS = {
    "password123456",
    "admin12345678",
    "sentinel123456",
    "changeme12345",
    "welcome123456",
    "letmein123456",
    "qwerty123456",
    "123456789012",
}

# Regex for standard RFC 5322 email syntax
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# UUID regex pattern
UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# SQL Injection indicator fragments
SQLI_PATTERNS = [
    re.compile(r"(--|/\*|\*/|;|\|\|)", re.IGNORECASE),
    re.compile(
        r"\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT|SELECT\s+.*FROM|DROP\s+TABLE|INSERT\s+INTO)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(EXEC|EXECUTE|XP_CMDSHELL)\b", re.IGNORECASE),
]


def validate_email(email: str) -> str:
    """Validate RFC email format, maximum length, and normalize to lowercase."""
    if not email or not isinstance(email, str):
        raise AppValidationError("Email is required and must be a string.")
    cleaned = email.strip()
    if len(cleaned) > 255:
        raise AppValidationError("Email exceeds maximum allowed length of 255 characters.")
    if not EMAIL_REGEX.match(cleaned):
        raise AppValidationError(f"Invalid email format: '{cleaned}'")
    return cleaned.lower()


def validate_password(password: str) -> str:
    """Validate password meets security policy (12-128 chars, no common breach passwords)."""
    if not password or not isinstance(password, str):
        raise AppValidationError("Password is required and must be a string.")
    # Never truncate silently
    if len(password) < 12:
        raise AppValidationError("Password must be at least 12 characters in length.")
    if len(password) > 128:
        raise AppValidationError("Password exceeds maximum allowed length of 128 characters.")
    if password.lower() in BREACHED_PASSWORDS:
        raise AppValidationError(
            "Password is too common or easily guessable. Please choose a stronger passphrase."
        )
    return password


def validate_uuid(val: str, field_name: str = "identifier") -> str:
    """Strictly parse and validate a UUIDv4 string."""
    if not val or not isinstance(val, str):
        raise AppValidationError(f"{field_name} must be a valid UUID string.")
    try:
        parsed = uuid.UUID(val.strip())
        return str(parsed).lower()
    except (ValueError, AttributeError) as exc:
        raise AppValidationError(f"{field_name} '{val}' is not a valid UUID.") from exc


def validate_ip_address(ip_str: str) -> str:
    """Strictly parse IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        raise AppValidationError("IP address is required.")
    cleaned = ip_str.strip()
    try:
        parsed = ipaddress.ip_address(cleaned)
        return str(parsed)
    except ValueError as exc:
        raise AppValidationError(f"Invalid IP address format: '{cleaned}'") from exc


def validate_port(port: int | str, field_name: str = "port") -> int:
    """Validate port number is an integer in the valid range 1-65535."""
    try:
        port_num = int(port)
    except (ValueError, TypeError) as exc:
        raise AppValidationError(f"{field_name} must be an integer between 1 and 65535.") from exc
    if not (1 <= port_num <= 65535):
        raise AppValidationError(f"{field_name} must be between 1 and 65535, received {port_num}.")
    return port_num


def validate_protocol(protocol: str) -> str:
    """Validate network protocol is in the strict allowlist (TCP, UDP, ICMP)."""
    if not protocol or not isinstance(protocol, str):
        raise AppValidationError("Protocol is required.")
    cleaned = protocol.strip().upper()
    if cleaned not in ALLOWED_PROTOCOLS:
        raise AppValidationError(
            f"Unsupported protocol '{protocol}'. Allowed: {sorted(ALLOWED_PROTOCOLS)}"
        )
    return cleaned


def validate_severity(severity: str) -> str:
    """Validate severity against allowlist (LOW, MEDIUM, HIGH, CRITICAL)."""
    if not severity or not isinstance(severity, str):
        raise AppValidationError("Severity is required.")
    cleaned = severity.strip().upper()
    if cleaned not in ALLOWED_SEVERITIES:
        raise AppValidationError(
            f"Invalid severity '{severity}'. Allowed: {sorted(ALLOWED_SEVERITIES)}"
        )
    return cleaned


def validate_incident_status(status: str) -> str:
    """Validate incident status against allowlist."""
    if not status or not isinstance(status, str):
        raise AppValidationError("Status is required.")
    cleaned = status.strip().upper()
    if cleaned not in ALLOWED_INCIDENT_STATUSES:
        raise AppValidationError(
            f"Invalid status '{status}'. Allowed: {sorted(ALLOWED_INCIDENT_STATUSES)}"
        )
    return cleaned


def validate_search_query(query: str, max_length: int = 100) -> str:
    """Validate and sanitize user search input to prevent SQL injection fragments."""
    if not query or not isinstance(query, str):
        return ""
    cleaned = query.strip()
    if len(cleaned) > max_length:
        raise AppValidationError(f"Search query exceeds maximum length of {max_length} characters.")
    for sqli_regex in SQLI_PATTERNS:
        if sqli_regex.search(cleaned):
            raise AppValidationError(
                "Search query contains illegal or potentially malicious characters."
            )
    return cleaned


def validate_date_range(
    start_date: str | datetime,
    end_date: str | datetime,
    max_days: int = 90,
) -> Tuple[datetime, datetime]:
    """Parse and validate date range: ISO-8601, UTC timezone-aware, start <= end, bounded range."""

    def _parse_date(dt: str | datetime) -> datetime:
        if isinstance(dt, datetime):
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        try:
            # Parse ISO-8601 string
            parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception as exc:
            raise AppValidationError(f"Invalid ISO-8601 date format: '{dt}'") from exc

    parsed_start = _parse_date(start_date)
    parsed_end = _parse_date(end_date)

    if parsed_start > parsed_end:
        raise AppValidationError("start_date cannot be greater than end_date.")

    duration_days = (parsed_end - parsed_start).total_seconds() / 86400.0
    if duration_days > max_days:
        raise AppValidationError(f"Date range exceeds maximum permitted window of {max_days} days.")

    return parsed_start, parsed_end


def validate_scores(
    confidence: Optional[float | Decimal] = None,
    risk_score: Optional[float | Decimal] = None,
    anomaly_score: Optional[float | Decimal] = None,
) -> None:
    """Validate confidence [0, 1] and risk score [0, 100]."""
    if confidence is not None:
        dec_conf = Decimal(str(confidence))
        if not (Decimal("0") <= dec_conf <= Decimal("1")):
            raise AppValidationError(
                f"Confidence score must be between 0.0 and 1.0, received {confidence}."
            )

    if risk_score is not None:
        dec_risk = Decimal(str(risk_score))
        if not (Decimal("0") <= dec_risk <= Decimal("100")):
            raise AppValidationError(
                f"Risk score must be between 0.0 and 100.0, received {risk_score}."
            )


def validate_string(
    val: str, field_name: str = "field", min_length: int = 1, max_length: int = 255
) -> str:
    """Validate string length bounds and strip dangerous control characters."""
    if not isinstance(val, str):
        raise AppValidationError(f"{field_name} must be a string.")
    cleaned = "".join(c for c in val if c.isprintable() or c in ("\n", "\r", "\t")).strip()
    if len(cleaned) < min_length:
        raise AppValidationError(f"{field_name} must be at least {min_length} characters.")
    if len(cleaned) > max_length:
        raise AppValidationError(f"{field_name} cannot exceed {max_length} characters.")
    return cleaned

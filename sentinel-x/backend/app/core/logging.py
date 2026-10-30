"""Structured JSON Logging System with Security Redaction.

Adheres strictly to Section 36 of architecture.md:
- Outputs standardized, structured JSON logs.
- Automatically correlates logs using request_id from context.
- Implements an automated redaction layer for sensitive fields, tokens, keys, and credentials.
"""

import contextvars
import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# ContextVar for async request_id propagation
request_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "request_id", default=None
)
user_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("user_id", default=None)

# Sensitive keys to scrub recursively in dicts
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "jwt_secret",
    "jwt_refresh_secret",
    "admin_bootstrap_secret",
    "model_signing_key",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "apikey",
    "api_token",
    "key",
    "private_key",
    "credentials",
    "cookie",
    "set-cookie",
    "database_url",
    "redis_url",
    "celery_broker_url",
    "virustotal_api_key",
    "abuseipdb_api_key",
}

# Regex patterns for masking sensitive strings in free-form messages
SENSITIVE_PATTERNS = [
    # Bearer tokens (JWTs or hex)
    (
        re.compile(
            r"Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+)", re.IGNORECASE
        ),
        "Bearer [REDACTED_JWT]",
    ),
    (re.compile(r"Bearer\s+([A-Za-z0-9_\-\.]{16,})", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    # DB connection passwords e.g. postgresql://user:password@host
    (re.compile(r"://([^:]+):([^@]+)@", re.IGNORECASE), r"://\1:[REDACTED]@"),
    # Key=value or "key": "value" patterns
    (
        re.compile(
            r'(["\']?(?:password|token|secret|api_?key)["\']?\s*[:=]\s*["\'])([^"\', \n]+)(["\']?)',
            re.IGNORECASE,
        ),
        r"\1[REDACTED]\3",
    ),
]


def redact_data(obj: Any) -> Any:
    """Recursively scrub sensitive keys and patterns from dictionary/list structures."""
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            key_lower = str(k).lower().strip()
            if any(sensitive in key_lower for sensitive in SENSITIVE_KEYS):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_data(v)
        return redacted
    elif isinstance(obj, list):
        return [redact_data(item) for item in obj]
    elif isinstance(obj, str):
        return redact_string(obj)
    return obj


def redact_string(text: str) -> str:
    """Scrub sensitive patterns from raw log message strings."""
    if not text:
        return text
    sanitized = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class StructuredJsonFormatter(logging.Formatter):
    """Custom logging formatter outputting clean, machine-parsable JSON with redaction."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_string(record.getMessage()),
        }

        # Correlate with request_id and user_id from context or record
        req_id = getattr(record, "request_id", None) or request_id_ctx.get()
        if req_id:
            log_payload["request_id"] = req_id

        user_id = getattr(record, "user_id", None) or user_id_ctx.get()
        if user_id:
            log_payload["user_id"] = user_id

        # Security/SOC contextual fields
        for field in ("action", "resource", "result", "source_ip", "path", "method", "status_code"):
            if hasattr(record, field):
                log_payload[field] = getattr(record, field)

        # Include structured extra data safely
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_payload["data"] = redact_data(record.extra_data)

        # Include exception info if present
        if record.exc_info:
            log_payload["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else "UnknownException",
                "message": redact_string(str(record.exc_info[1])),
            }

        return json.dumps(log_payload)


def setup_logging(log_level: str = "INFO") -> None:
    """Initialize structured JSON logging for root and major framework loggers."""
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level.upper())

    # Remove existing handlers to avoid duplicate output
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(StructuredJsonFormatter())
    root_logger.addHandler(stream_handler)

    # Apply formatter to uvicorn and fastapi loggers
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        lib_logger = logging.getLogger(logger_name)
        lib_logger.handlers = []
        lib_logger.addHandler(stream_handler)
        lib_logger.propagate = False

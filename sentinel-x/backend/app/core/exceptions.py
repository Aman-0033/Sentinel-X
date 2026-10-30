"""Centralized Exception Handling and Safe Error Envelopes.

Strictly enforces Section 14 and Section 37 of architecture.md:
- Client-facing responses contain ONLY safe code, message, and request_id.
- Never exposes tracebacks, SQL statements, credentials, filesystem paths, or secrets.
- Full diagnostic context is safely logged to server logs.
"""

import logging
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.logging import request_id_ctx
from app.schemas.common import ErrorDetail, ErrorResponse

logger = logging.getLogger("sentinel.exceptions")


class SentinelException(Exception):
    """Base application exception with safe error code and HTTP status mapping."""

    def __init__(
        self,
        message: str = "An internal security error occurred.",
        code: str = "INTERNAL_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


class ConfigurationError(SentinelException):
    """Raised when critical configuration is missing or invalid."""

    def __init__(self, message: str = "Invalid or missing application configuration.") -> None:
        super().__init__(
            message=message,
            code="CONFIGURATION_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class AuthenticationError(SentinelException):
    """Raised when authentication credentials are missing, invalid, or expired."""

    def __init__(self, message: str = "Authentication failed or token invalid.") -> None:
        super().__init__(
            message=message,
            code="AUTHENTICATION_FAILED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class AuthorizationError(SentinelException):
    """Raised when client lacks permission for the requested action."""

    def __init__(self, message: str = "Access denied. Insufficient permissions.") -> None:
        super().__init__(
            message=message,
            code="AUTHORIZATION_DENIED",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class NotFoundError(SentinelException):
    """Raised when a requested resource does not exist."""

    def __init__(self, resource: str = "Resource", identifier: Optional[str] = None) -> None:
        id_str = f" '{identifier}'" if identifier else ""
        super().__init__(
            message=f"{resource}{id_str} was not found.",
            code="NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ConflictError(SentinelException):
    """Raised when a resource state conflict occurs (e.g. duplicate key)."""

    def __init__(self, message: str = "Resource already exists or is in conflict.") -> None:
        super().__init__(
            message=message,
            code="CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
        )


class RateLimitError(SentinelException):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str = "Rate limit exceeded. Please retry later.") -> None:
        super().__init__(
            message=message,
            code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )


class ServiceUnavailableError(SentinelException):
    """Raised when backing infrastructure or dependency is unreachable."""

    def __init__(self, message: str = "Service or dependency is currently unavailable.") -> None:
        super().__init__(
            message=message,
            code="SERVICE_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class AppValidationError(SentinelException):
    """Raised for input validation failures."""

    def __init__(
        self, message: str = "Input validation failed.", details: Optional[Any] = None
    ) -> None:
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


def _get_request_id(request: Request) -> str:
    """Retrieve request ID from request state or contextvar."""
    return getattr(request.state, "request_id", None) or request_id_ctx.get() or "unknown"


async def sentinel_exception_handler(request: Request, exc: SentinelException) -> JSONResponse:
    """Handle custom SentinelException domain errors."""
    req_id = _get_request_id(request)
    logger.warning(
        f"Domain exception: {exc.code} - {exc.message}",
        extra={"request_id": req_id, "status_code": exc.status_code, "action": "exception_handled"},
    )
    payload = ErrorResponse(
        error=ErrorDetail(
            code=exc.code,
            message=exc.message,
            request_id=req_id,
            details=exc.details,
        )
    )
    return JSONResponse(status_code=exc.status_code, content=payload.model_dump(exclude_none=True))


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic/FastAPI request validation errors cleanly without leaking internals."""
    req_id = _get_request_id(request)
    safe_errors = []
    for err in exc.errors():
        loc = " -> ".join(str(p) for p in err.get("loc", []))
        safe_errors.append({"field": loc, "issue": err.get("msg", "Invalid input")})

    logger.info(
        "Request validation failed",
        extra={"request_id": req_id, "action": "validation_failed"},
    )
    payload = ErrorResponse(
        error=ErrorDetail(
            code="VALIDATION_ERROR",
            message="Request input validation failed.",
            request_id=req_id,
            details=safe_errors,
        )
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=payload.model_dump(exclude_none=True),
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle standard Starlette/FastAPI HTTPExceptions."""
    req_id = _get_request_id(request)
    code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        422: "UNPROCESSABLE_ENTITY",
        429: "TOO_MANY_REQUESTS",
        500: "INTERNAL_SERVER_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }
    code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")
    message = str(exc.detail) if exc.detail else "An HTTP error occurred."

    logger.warning(
        f"HTTP error {exc.status_code}: {message}",
        extra={"request_id": req_id, "status_code": exc.status_code},
    )
    payload = ErrorResponse(
        error=ErrorDetail(
            code=code,
            message=message,
            request_id=req_id,
        )
    )
    return JSONResponse(status_code=exc.status_code, content=payload.model_dump(exclude_none=True))


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global catch-all exception handler. Protects against leaking stack traces or credentials."""
    req_id = _get_request_id(request)
    logger.exception(
        f"Unhandled server error during request processing: {exc}",
        extra={"request_id": req_id, "action": "unhandled_exception"},
    )
    payload = ErrorResponse(
        error=ErrorDetail(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected internal server error occurred. Request ID logged for investigation.",
            request_id=req_id,
        )
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=payload.model_dump(exclude_none=True),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all centralized safe exception handlers on the FastAPI application."""
    app.add_exception_handler(SentinelException, sentinel_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

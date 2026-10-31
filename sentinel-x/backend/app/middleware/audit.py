"""Audit Logging Middleware.

Records structured audit telemetry for mutating operations (POST, PUT, PATCH, DELETE)
strictly adhering to Section 36 (Zero secret leakage in logs).
"""

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("sentinel.audit")


class AuditMiddleware(BaseHTTPMiddleware):
    """Logs mutating requests with metadata for forensic visibility."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Audit write/mutating operations and authentication endpoints
        if request.method in ("POST", "PUT", "PATCH", "DELETE") or request.url.path.startswith("/api/v1/auth"):
            user_id = getattr(request.state, "user_id", None) or "anonymous"
            client_ip = request.client.host if request.client else "unknown"
            request_id = getattr(request.state, "request_id", "")

            logger.info(
                f"HTTP {request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)",
                extra={
                    "request_id": request_id,
                    "user_id": user_id,
                    "action": f"http_{request.method.lower()}",
                    "resource": request.url.path,
                    "result": "SUCCESS" if response.status_code < 400 else "FAILURE",
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "source_ip": client_ip,
                },
            )

        return response


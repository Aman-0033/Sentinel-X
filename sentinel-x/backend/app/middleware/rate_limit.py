"""Global Rate Limiting Middleware.

Enforces baseline unauthenticated and authenticated rate limits per Section 31:
- Unauthenticated traffic: 120 req/min/IP
- Health endpoints (/health) are exempt to prevent monitor disruption.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.rate_limit import check_rate_limit


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces baseline rate-limiting protection across all incoming endpoints."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Exempt health probes from rate limits
        if request.url.path.startswith("/health") or request.method == "OPTIONS":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        user_id = getattr(request.state, "user_id", None)

        # Authenticated vs unauthenticated rate keys
        if user_id:
            key = f"mw:user:{user_id}"
            limit = 300  # Authenticated baseline
        else:
            key = f"mw:ip:{client_ip}"
            limit = 120  # Unauthenticated baseline

        allowed, remaining, reset_time = check_rate_limit(key, limit=limit, window_seconds=60)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Global rate limit of {limit} req/min exceeded. Try again in {reset_time}s.",
                        "details": {},
                    },
                    "meta": {"request_id": getattr(request.state, "request_id", "")},
                },
                headers={
                    "Retry-After": str(max(1, reset_time)),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_time),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
        return response

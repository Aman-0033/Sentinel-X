"""Authentication Context Middleware.

Inspects incoming HTTP requests for Authorization headers, populating request.state
with validated authentication context (user_id, role) when present.
"""

from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.security import decode_access_token


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Inspects Bearer tokens and attaches user context to request.state."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.user_id = None
        request.state.user_role = None
        request.state.user_email = None

        auth_header: Optional[str] = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            try:
                payload = decode_access_token(token)
                request.state.user_id = payload.get("sub")
                request.state.user_role = payload.get("role")
                request.state.user_email = payload.get("email")
            except Exception:
                # Malformed or expired tokens will be strictly rejected by route-level dependencies
                pass

        return await call_next(request)


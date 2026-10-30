"""Request ID Middleware.

Generates or propagates a unique correlation ID for every incoming HTTP request.
Sets the ID in the logging context and attaches it to the response headers.
"""

import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import request_id_ctx

REQUEST_ID_HEADER = "X-Request-ID"
SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Middleware attaching a validated or generated Request-ID to context and response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming_id = request.headers.get(REQUEST_ID_HEADER)

        # Validate incoming ID or generate fresh UUID4
        if incoming_id and SAFE_ID_PATTERN.match(incoming_id):
            request_id = incoming_id
        else:
            request_id = uuid.uuid4().hex

        # Set into contextvar for logging and state for handlers
        token = request_id_ctx.set(request_id)
        request.state.request_id = request_id

        try:
            response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        finally:
            request_id_ctx.reset(token)

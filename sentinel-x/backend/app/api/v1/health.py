"""Health Check Controller.

Provides liveness and readiness probes complying with Section 14 and Section 45:
- GET /health/live: Immediate 200 OK liveness indicator.
- GET /health/ready: Multi-dependency readiness probe checking PostgreSQL and Redis.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Request, Response, status

from app.core.config import get_settings
from app.core.logging import request_id_ctx
from app.core.redis import check_redis_connection
from app.db.session import check_db_connection

router = APIRouter(tags=["Health"])
settings = get_settings()


def _get_req_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or request_id_ctx.get() or "unknown"


@router.get("/live", status_code=status.HTTP_200_OK)
async def liveness_probe(request: Request) -> Dict[str, Any]:
    """Liveness probe indicating application server is running and accepting connections."""
    req_id = _get_req_id(request)
    return {
        "status": "healthy",
        "data": {
            "status": "live",
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "meta": {
            "request_id": req_id,
        },
    }


@router.get("/ready")
async def readiness_probe(request: Request, response: Response) -> Dict[str, Any]:
    """Readiness probe verifying operational state of PostgreSQL and Redis dependencies."""
    req_id = _get_req_id(request)
    db_ok = check_db_connection()
    redis_ok = check_redis_connection()

    dependencies = {
        "database": "connected" if db_ok else "disconnected",
        "redis": "connected" if redis_ok else "disconnected",
    }

    if db_ok and redis_ok:
        response.status_code = status.HTTP_200_OK
        return {
            "status": "ready",
            "data": {
                "status": "ready",
                "dependencies": dependencies,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "meta": {
                "request_id": req_id,
            },
        }

    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "not_ready",
        "error": {
            "code": "SERVICE_UNAVAILABLE",
            "message": "Critical backing infrastructure is currently unreachable.",
            "request_id": req_id,
        },
        "data": {
            "status": "not_ready",
            "dependencies": dependencies,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "meta": {
            "request_id": req_id,
        },
    }

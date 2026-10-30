"""Redis Connection Management and Health Checking.

Provides pooled Redis clients and a non-blocking readiness probe.
"""

import logging
from typing import Optional

import redis

from app.core.config import get_settings

logger = logging.getLogger("sentinel.redis")

_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    """Return a singleton Redis client with connection pooling."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = redis.from_url(
            settings.REDIS_URL,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
            decode_responses=True,
        )
    return _redis_client


def check_redis_connection() -> bool:
    """Safe Redis readiness probe. Pings Redis server with short timeout."""
    try:
        client = get_redis_client()
        return bool(client.ping())
    except Exception as exc:
        logger.warning(f"Redis readiness check failed: {exc.__class__.__name__}")
        return False


def close_redis_connection() -> None:
    """Close Redis connection pool during application shutdown."""
    global _redis_client
    if _redis_client is not None:
        try:
            _redis_client.close()
        except Exception:
            pass
        _redis_client = None

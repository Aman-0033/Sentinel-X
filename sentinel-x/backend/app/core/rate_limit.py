"""Redis-backed Rate Limiter with In-Memory Resilient Fallback.

Strictly enforces Section 31 of architecture.md:
- Rate limits unauthenticated and authenticated traffic.
- Protects security-sensitive endpoints (login, refresh, ingestion).
- Includes resilient circuit breaker when Redis is unavailable.
"""

import time
from typing import Dict, Optional, Tuple

from app.core.exceptions import RateLimitError
from app.core.redis import get_redis_client

# In-memory sliding window fallback store for testing or Redis unavailability
_in_memory_store: Dict[str, list] = {}
_redis_last_failed: float = 0.0


def _check_in_memory(
    key: str, limit: int, window_seconds: int, now: float
) -> Tuple[bool, int, int]:
    """In-memory sliding window counter."""
    global _in_memory_store
    reset_time = int(now + window_seconds)
    timestamps = _in_memory_store.get(key, [])
    timestamps = [ts for ts in timestamps if now - ts < window_seconds]

    if len(timestamps) >= limit:
        _in_memory_store[key] = timestamps
        return False, 0, reset_time

    timestamps.append(now)
    _in_memory_store[key] = timestamps
    remaining = max(0, limit - len(timestamps))
    return True, remaining, reset_time


def check_rate_limit(
    key: str,
    limit: int,
    window_seconds: int = 60,
    redis_client: Optional[object] = None,
) -> Tuple[bool, int, int]:
    """Check if the given key has exceeded the rate limit within the sliding window.

    Returns:
        (is_allowed: bool, remaining_requests: int, reset_time_epoch: int)
    """
    global _redis_last_failed
    now = time.time()
    reset_time = int(now + window_seconds)

    # Circuit breaker: if Redis failed within last 5 seconds, use in-memory directly
    if now - _redis_last_failed < 5.0 and redis_client is None:
        return _check_in_memory(key, limit, window_seconds, now)

    try:
        client = redis_client or get_redis_client()
        redis_key = f"ratelimit:{key}"

        pipe = client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
        pipe.zcard(redis_key)
        pipe.zadd(redis_key, {str(now): now})
        pipe.expire(redis_key, window_seconds + 5)
        results = pipe.execute()

        current_count = results[1]
        remaining = max(0, limit - (current_count + 1))

        if current_count >= limit:
            return False, 0, reset_time
        return True, remaining, reset_time

    except Exception:
        _redis_last_failed = now
        return _check_in_memory(key, limit, window_seconds, now)


def enforce_rate_limit(key: str, limit: int, window_seconds: int = 60) -> None:
    """Enforce rate limit, raising RateLimitError if quota exceeded."""
    allowed, remaining, reset_time = check_rate_limit(key, limit, window_seconds)
    if not allowed:
        raise RateLimitError(
            f"Rate limit of {limit} requests per {window_seconds}s exceeded. Try again in {reset_time - int(time.time())}s."
        )


def reset_rate_limit(key: str) -> None:
    """Clear rate limit counter for a specific key."""
    global _redis_last_failed
    if time.time() - _redis_last_failed >= 5.0:
        try:
            client = get_redis_client()
            client.delete(f"ratelimit:{key}")
        except Exception:
            _redis_last_failed = time.time()
    if key in _in_memory_store:
        del _in_memory_store[key]

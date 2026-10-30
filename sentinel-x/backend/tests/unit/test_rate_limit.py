"""Unit tests for rate limiting (Section 31)."""

import pytest

from app.core.exceptions import RateLimitError
from app.core.rate_limit import check_rate_limit, enforce_rate_limit, reset_rate_limit


def test_rate_limit_allows_under_quota():
    """Verify requests under limit pass with proper remaining count."""
    key = "test_ip_192.168.1.5"
    reset_rate_limit(key)

    allowed, remaining, _ = check_rate_limit(key, limit=5, window_seconds=60)
    assert allowed is True
    assert remaining == 4

    allowed, remaining, _ = check_rate_limit(key, limit=5, window_seconds=60)
    assert allowed is True
    assert remaining == 3


def test_rate_limit_blocks_when_quota_exceeded():
    """Verify rate limit blocks once quota is exhausted."""
    key = "test_user_exceeded"
    reset_rate_limit(key)

    # Consume quota
    for _ in range(3):
        allowed, _, _ = check_rate_limit(key, limit=3, window_seconds=60)
        assert allowed is True

    # 4th request should fail
    allowed, remaining, _ = check_rate_limit(key, limit=3, window_seconds=60)
    assert allowed is False
    assert remaining == 0

    with pytest.raises(RateLimitError):
        enforce_rate_limit(key, limit=3, window_seconds=60)

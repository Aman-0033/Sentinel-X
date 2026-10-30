"""Unit tests for Redis connection management and health checking."""

from unittest.mock import MagicMock, patch

from app.core.redis import check_redis_connection, close_redis_connection, get_redis_client


def test_get_redis_client_and_close():
    """Verify get_redis_client creates client and close_redis_connection cleans it up."""
    with patch("redis.from_url") as mock_from_url:
        mock_instance = MagicMock()
        mock_from_url.return_value = mock_instance

        # Clean previous state
        close_redis_connection()

        client = get_redis_client()
        assert client is mock_instance

        # Subsequent call returns same instance (singleton)
        client2 = get_redis_client()
        assert client2 is mock_instance
        assert mock_from_url.call_count == 1

        close_redis_connection()
        mock_instance.close.assert_called_once()


def test_check_redis_connection_success():
    """Verify check_redis_connection returns True when ping returns PONG."""
    with patch("app.core.redis.get_redis_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_get_client.return_value = mock_client

        assert check_redis_connection() is True


def test_check_redis_connection_failure():
    """Verify check_redis_connection returns False when ping raises exception."""
    with patch("app.core.redis.get_redis_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.ping.side_effect = Exception("Connection timed out")
        mock_get_client.return_value = mock_client

        assert check_redis_connection() is False

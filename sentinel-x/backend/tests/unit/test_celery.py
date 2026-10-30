"""Unit tests for Celery configuration and broker health checks."""

from unittest.mock import patch

from app.workers.celery_app import celery_app, check_celery_broker


def test_celery_configuration():
    """Verify Celery app has JSON serialization and security settings configured."""
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"
    assert "json" in celery_app.conf.accept_content
    assert celery_app.conf.timezone == "UTC"
    assert celery_app.conf.enable_utc is True


def test_check_celery_broker_failure_handled_safely():
    """Verify check_celery_broker returns False without unhandled exceptions when broker is unreachable."""
    with patch.object(
        celery_app, "connection_for_read", side_effect=Exception("Redis connection refused")
    ):
        assert check_celery_broker() is False

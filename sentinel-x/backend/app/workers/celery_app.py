"""Celery Application Initialization and Task Configuration.

Configures asynchronous background workers for ML inference, threat-intel enrichment,
and report generation per Section 5 of architecture.md.
"""

import logging

from celery import Celery

from app.core.config import get_settings

logger = logging.getLogger("sentinel.celery")

settings = get_settings()

celery_app = Celery(
    "sentinel_x",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

# Secure configuration: JSON-only serialization, UTC timezone
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour hard limit
    task_soft_time_limit=3300,  # 55 minutes soft limit
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)


def check_celery_broker() -> bool:
    """Safe check for Celery broker connectivity."""
    try:
        with celery_app.connection_for_read() as conn:
            conn.connect()
        return True
    except Exception as exc:
        logger.warning(f"Celery broker check failed: {exc.__class__.__name__}")
        return False

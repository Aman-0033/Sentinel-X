"""Celery background tasks for asynchronous ML threat detection."""

import logging
from typing import List

from app.db.session import SessionLocal
from app.services.detection_service import DetectionService
from app.workers.celery_app import celery_app

logger = logging.getLogger("sentinel.workers.detection")


@celery_app.task(name="tasks.analyze_flow_batch")
def analyze_flow_batch_task(flow_ids: List[str]) -> int:
    """Background task to analyze a batch of network flows via ML models."""
    logger.info(f"Starting batch analysis for {len(flow_ids)} flows.")
    db = SessionLocal()
    try:
        service = DetectionService(db)
        detections = service.analyze_flow_batch(flow_ids)
        logger.info(f"Completed analysis. Generated {len(detections)} detections.")
        return len(detections)
    except Exception as exc:
        logger.error(f"Error analyzing flow batch: {str(exc)}")
        raise
    finally:
        db.close()

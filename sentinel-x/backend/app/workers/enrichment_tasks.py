"""Celery background tasks for threat intelligence enrichment."""

import asyncio
import logging
from typing import Optional

from app.db.models.detection import Detection
from app.db.session import SessionLocal
from app.services.threat_intel_service import ThreatIntelService
from app.workers.celery_app import celery_app

logger = logging.getLogger("sentinel.workers.enrichment")


@celery_app.task(name="tasks.enrich_detection")
def enrich_detection_task(detection_id: str, provider: str = "virustotal") -> Optional[str]:
    """Background task to enrich a detection's source IP with external threat intel."""
    logger.info(f"Starting enrichment task for detection {detection_id} using {provider}.")
    db = SessionLocal()
    try:
        detection = db.query(Detection).filter(Detection.id == detection_id).first()
        if not detection or not detection.flow:
            logger.warning(f"Detection {detection_id} or associated flow not found.")
            return None

        ip_to_check = detection.flow.source_ip
        service = ThreatIntelService(db)

        # Run async enrichment in sync Celery task
        result = asyncio.run(
            service.enrich_ip(ip_address=ip_to_check, provider=provider, detection_id=detection_id)
        )
        logger.info(f"Enrichment completed for {ip_to_check}: verdict={result.verdict}")
        return result.verdict
    except Exception as exc:
        logger.error(f"Error enriching detection {detection_id}: {str(exc)}")
        raise
    finally:
        db.close()

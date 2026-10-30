"""Celery background tasks for quarantined file ingestion."""

import logging
from pathlib import Path
from typing import Optional

from app.db.session import SessionLocal
from app.services.ingestion_service import IngestionService
from app.workers.celery_app import celery_app

logger = logging.getLogger("sentinel.workers.ingestion")


@celery_app.task(name="tasks.process_quarantined_upload")
def process_quarantined_upload_task(
    file_path: str,
    original_filename: str,
    source_id: Optional[str] = None,
) -> int:
    """Background task to parse and ingest quarantined CSV or JSON files."""
    logger.info(f"Processing quarantined upload: {file_path}")
    db = SessionLocal()
    try:
        service = IngestionService(db)
        flows = service.process_quarantined_file(
            file_path=Path(file_path),
            original_filename=original_filename,
            source_id=source_id,
        )
        logger.info(f"Successfully processed {len(flows)} flows from {original_filename}.")
        return len(flows)
    except Exception as exc:
        logger.error(f"Error processing quarantined upload {file_path}: {str(exc)}")
        raise
    finally:
        db.close()

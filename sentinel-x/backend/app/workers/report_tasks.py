"""Celery background tasks for report generation."""

import logging

from app.db.session import SessionLocal
from app.services.report_service import ReportService
from app.workers.celery_app import celery_app

logger = logging.getLogger("sentinel.workers.report")


@celery_app.task(name="tasks.generate_report")
def generate_report_task(report_id: str) -> str:
    """Background task to generate and write a report file."""
    logger.info(f"Generating report {report_id} in background.")
    db = SessionLocal()
    try:
        service = ReportService(db)
        file_path = service.generate_report_content(report_id)
        logger.info(f"Report {report_id} generated successfully at {file_path}.")
        return str(file_path)
    except Exception as exc:
        logger.error(f"Error generating report {report_id}: {str(exc)}")
        raise
    finally:
        db.close()

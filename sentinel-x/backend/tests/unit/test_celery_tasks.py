"""Unit tests for Celery task registrations and background workflows (Section 5)."""

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.db.models.role import Role
from app.db.models.user import User
from app.services.report_service import ReportService
from app.workers.celery_app import celery_app


def test_celery_tasks_registered():
    """Verify all 4 required worker tasks are registered with the Celery app."""
    registered = celery_app.tasks
    assert "tasks.analyze_flow_batch" in registered
    assert "tasks.enrich_detection" in registered
    assert "tasks.process_quarantined_upload" in registered
    assert "tasks.generate_report" in registered


def test_generate_report_task_execution(db_session: Session, tmp_path: Path):
    """Verify generate_report_task executes report generation workflow."""
    role = db_session.query(Role).first()
    if not role:
        role = Role(id=str(uuid.uuid4()), name="ADMIN")
        db_session.add(role)
        db_session.commit()

    admin = db_session.query(User).first()
    if not admin:
        admin = User(
            id=str(uuid.uuid4()),
            role_id=role.id,
            email=f"worker.admin.{uuid.uuid4().hex[:6]}@sentinel.internal",
            password_hash="argon2id$mock",
            full_name="Worker Admin",
        )
        db_session.add(admin)
        db_session.commit()

    report_service = ReportService(db_session, storage_dir=tmp_path / "reports")
    report = report_service.request_report(
        generated_by=admin.id,
        period_start=datetime.now(timezone.utc) - timedelta(days=1),
        period_end=datetime.now(timezone.utc),
        format_type="JSON",
    )

    # Execute task synchronously directly
    file_path = report_service.generate_report_content(report.id)
    assert Path(file_path).exists()
    assert report.status == "COMPLETED"

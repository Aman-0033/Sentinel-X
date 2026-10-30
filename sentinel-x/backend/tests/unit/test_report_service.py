"""Unit tests for ReportService and report generation (Section 11.13 and Section 22)."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError
from app.db.models.role import Role
from app.db.models.user import User
from app.services.report_service import ReportService


@pytest.fixture
def report_fixture(db_session: Session, tmp_path: Path):
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
            email=f"report.admin.{uuid.uuid4().hex[:6]}@sentinel.internal",
            password_hash="argon2id$mock",
            full_name="Report Admin",
        )
        db_session.add(admin)
        db_session.commit()

    service = ReportService(db_session, storage_dir=tmp_path / "reports")
    return admin, service


def test_request_report_queued_status(report_fixture):
    admin, service = report_fixture
    start = datetime.now(timezone.utc) - timedelta(days=7)
    end = datetime.now(timezone.utc)

    report = service.request_report(
        generated_by=admin.id,
        period_start=start,
        period_end=end,
        format_type="JSON",
    )
    assert report.status == "QUEUED"
    assert report.format == "JSON"


def test_request_report_validation(report_fixture):
    admin, service = report_fixture
    now = datetime.now(timezone.utc)

    # Invalid format
    with pytest.raises(AppValidationError):
        service.request_report(
            generated_by=admin.id,
            period_start=now - timedelta(days=1),
            period_end=now,
            format_type="EXE",
        )

    # Inverted date range
    with pytest.raises(AppValidationError):
        service.request_report(
            generated_by=admin.id,
            period_start=now,
            period_end=now - timedelta(days=1),
            format_type="JSON",
        )


def test_generate_json_report(report_fixture):
    admin, service = report_fixture
    start = datetime.now(timezone.utc) - timedelta(days=7)
    end = datetime.now(timezone.utc)

    report = service.request_report(admin.id, start, end, format_type="JSON")
    file_path = service.generate_report_content(report.id)

    assert Path(file_path).exists()
    assert report.status == "COMPLETED"

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "total_detections" in data
    assert "total_incidents" in data


def test_generate_csv_report(report_fixture):
    admin, service = report_fixture
    start = datetime.now(timezone.utc) - timedelta(days=7)
    end = datetime.now(timezone.utc)

    report = service.request_report(admin.id, start, end, format_type="CSV")
    file_path = service.generate_report_content(report.id)

    assert Path(file_path).exists()
    assert file_path.suffix == ".csv"
    assert report.status == "COMPLETED"


def test_generate_pdf_report(report_fixture):
    admin, service = report_fixture
    start = datetime.now(timezone.utc) - timedelta(days=7)
    end = datetime.now(timezone.utc)

    report = service.request_report(admin.id, start, end, format_type="PDF")
    file_path = service.generate_report_content(report.id)

    assert Path(file_path).exists()
    assert file_path.suffix == ".pdf"
    assert report.status == "COMPLETED"

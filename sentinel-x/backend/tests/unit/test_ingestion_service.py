"""Unit tests for IngestionService and quarantine pipeline (Section 30 and Section 32)."""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError
from app.services.ingestion_service import IngestionService, sanitize_csv_cell


@pytest.fixture
def db_session(app) -> Session:
    from app.db.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def test_sanitize_csv_cell():
    """Verify formula injection prefixes are neutralized."""
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert sanitize_csv_cell("-5+2") == "'-5+2"
    assert sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert sanitize_csv_cell("normal_text") == "normal_text"


def test_ingest_flow_batch_success(db_session: Session):
    """Verify valid batch of network flows is normalized and persisted."""
    service = IngestionService(db_session)
    now = datetime.now(timezone.utc)

    batch = [
        {
            "timestamp": now.isoformat(),
            "source_ip": "192.168.1.50",
            "source_port": 54321,
            "destination_ip": "10.0.0.10",
            "destination_port": 443,
            "protocol": "TCP",
            "packets": 12,
            "bytes": 1024,
            "duration_ms": 45.2,
            "direction": "OUTBOUND",
        },
        {
            "timestamp": now.isoformat(),
            "source_ip": "172.16.0.4",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "destination_port": 53,
        },
    ]

    persisted = service.ingest_flow_batch(batch)
    assert len(persisted) == 2
    assert persisted[0].id is not None
    assert persisted[0].source_ip == "192.168.1.50"
    assert persisted[0].protocol == "TCP"
    assert persisted[1].protocol == "UDP"


def test_ingest_flow_batch_rejects_oversized_batch(db_session: Session):
    """Verify batches exceeding MAX_BATCH_FLOW_COUNT (1000) are rejected."""
    service = IngestionService(db_session)
    oversized = [{"dummy": i} for i in range(1001)]

    with pytest.raises(AppValidationError) as exc:
        service.ingest_flow_batch(oversized)
    assert "exceeds maximum limit" in str(exc.value)


def test_ingest_flow_batch_rejects_invalid_flow_data(db_session: Session):
    """Verify invalid flow attributes trigger validation errors."""
    service = IngestionService(db_session)

    # Invalid source_ip
    with pytest.raises(AppValidationError):
        service.ingest_flow_batch(
            [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": "bad_ip",
                    "destination_ip": "10.0.0.1",
                }
            ]
        )

    # Invalid port (>65535)
    with pytest.raises(AppValidationError):
        service.ingest_flow_batch(
            [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": "10.0.0.1",
                    "destination_ip": "10.0.0.2",
                    "source_port": 99999,
                }
            ]
        )

    # Negative bytes
    with pytest.raises(AppValidationError):
        service.ingest_flow_batch(
            [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": "10.0.0.1",
                    "destination_ip": "10.0.0.2",
                    "bytes": -50,
                }
            ]
        )


def test_process_quarantined_csv_upload_with_injection_sanitization(
    db_session: Session, tmp_path: Path
):
    """Verify quarantined CSV upload processes correctly and cleans up quarantine file."""
    quarantine_dir = tmp_path / "quarantine"
    service = IngestionService(db_session, quarantine_dir=quarantine_dir)

    csv_content = (
        "timestamp,source_ip,destination_ip,protocol,source_port,destination_port,direction\n"
        "2026-10-30T12:00:00Z,192.168.1.1,10.0.0.1,TCP,1234,80,=DDE_CMD\n"
    ).encode("utf-8")

    count, persisted = service.process_quarantined_upload(
        file_bytes=csv_content,
        file_extension="csv",
    )

    assert count == 1
    assert persisted[0].direction == "'=DDE_CMD"  # Sanitized formula prefix
    # Quarantine file must be removed
    assert len(list(quarantine_dir.glob("*.csv"))) == 0


def test_process_quarantined_json_upload(db_session: Session, tmp_path: Path):
    """Verify quarantined JSON upload processing."""
    quarantine_dir = tmp_path / "quarantine"
    service = IngestionService(db_session, quarantine_dir=quarantine_dir)

    json_content = b"""
    [
        {
            "timestamp": "2026-10-30T12:30:00Z",
            "source_ip": "10.1.1.1",
            "destination_ip": "10.1.1.2",
            "protocol": "ICMP"
        }
    ]
    """

    count, persisted = service.process_quarantined_upload(
        file_bytes=json_content,
        file_extension="json",
    )

    assert count == 1
    assert persisted[0].protocol == "ICMP"
    assert len(list(quarantine_dir.glob("*.json"))) == 0


def test_upload_rejects_unsupported_extensions(db_session: Session):
    """Verify uploads reject executable or dangerous extensions."""
    service = IngestionService(db_session)

    with pytest.raises(AppValidationError) as exc:
        service.process_quarantined_upload(b"echo 1", file_extension="exe")
    assert "Unsupported file format" in str(exc.value)

    with pytest.raises(AppValidationError) as exc:
        service.process_quarantined_upload(b"<?php", file_extension="php")
    assert "Unsupported file format" in str(exc.value)

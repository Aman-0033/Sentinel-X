"""Unit tests for Incident Management and Automated Correlation Engine (Section 43)."""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from app.db.models.detection import Detection
from app.db.models.model_version import ModelVersion
from app.db.models.network_flow import NetworkFlow
from app.db.models.role import Role
from app.db.models.user import User
from app.services.incident_service import IncidentService


@pytest.fixture
def correlation_fixture(db_session: Session):
    """Set up baseline database models for detection and correlation tests."""
    # Ensure role exists
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
            email=f"corr.admin.{uuid.uuid4().hex[:6]}@sentinel.internal",
            password_hash="argon2id$mock",
            full_name="Correlation Admin",
        )
        db_session.add(admin)
        db_session.commit()

    mv = db_session.query(ModelVersion).first()
    if not mv:
        now = datetime.now(timezone.utc)
        mv = ModelVersion(
            id=str(uuid.uuid4()),
            name="Corr Model",
            version="1.0.0",
            algorithm="XGBoost",
            artifact_uri="models/sentinel_xgb_v1.joblib",
            checksum="mock_checksum_64chars_abcdef0123456789abcdef0123456789abcdef0123456789",
            feature_schema={"features": ["packet_count"]},
            metrics={"f1": 1.0},
            status="ACTIVE",
            trained_at=now,
            created_by=admin.id,
            created_at=now,
        )
        db_session.add(mv)
        db_session.commit()

    return admin, mv


def test_benign_detection_does_not_create_incident(db_session: Session, correlation_fixture):
    admin, mv = correlation_fixture
    service = IncidentService(db_session)

    flow = NetworkFlow(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        protocol="TCP",
    )
    db_session.add(flow)

    det = Detection(
        id=str(uuid.uuid4()),
        flow_id=flow.id,
        model_version_id=mv.id,
        attack_type="Benign",
        confidence=0.98,
        risk_score=10.0,
        severity="LOW",
        is_anomaly=False,
        detected_at=datetime.now(timezone.utc),
    )
    db_session.add(det)
    db_session.commit()

    incident = service.correlate_detection(det, flow=flow, system_user_id=admin.id)
    assert incident is None


def test_malicious_detection_creates_incident_and_links(db_session: Session, correlation_fixture):
    admin, mv = correlation_fixture
    service = IncidentService(db_session)

    flow = NetworkFlow(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_ip="203.0.113.55",
        destination_ip="10.0.0.1",
        protocol="TCP",
    )
    db_session.add(flow)

    det = Detection(
        id=str(uuid.uuid4()),
        flow_id=flow.id,
        model_version_id=mv.id,
        attack_type="Port Scan",
        confidence=0.92,
        risk_score=45.0,
        severity="MEDIUM",
        is_anomaly=True,
        detected_at=datetime.now(timezone.utc),
    )
    db_session.add(det)
    db_session.commit()

    incident = service.correlate_detection(det, flow=flow, system_user_id=admin.id)
    assert incident is not None
    assert incident.status == "OPEN"
    assert incident.severity == "MEDIUM"
    assert "203.0.113.55" in incident.title
    assert len(incident.detections) == 1
    assert incident.detections[0].id == det.id
    assert len(incident.events) == 1
    assert incident.events[0].event_type == "INCIDENT_CREATED"


def test_correlation_attaches_to_existing_and_escalates_severity(
    db_session: Session, correlation_fixture
):
    admin, mv = correlation_fixture
    service = IncidentService(db_session)

    src_ip = f"198.51.100.{uuid.uuid4().hex[:2]}"

    # 1. First detection (MEDIUM severity)
    flow1 = NetworkFlow(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_ip=src_ip,
        destination_ip="10.0.0.1",
        protocol="TCP",
    )
    db_session.add(flow1)
    det1 = Detection(
        id=str(uuid.uuid4()),
        flow_id=flow1.id,
        model_version_id=mv.id,
        attack_type="Port Scan",
        confidence=0.85,
        risk_score=45.0,
        severity="MEDIUM",
        is_anomaly=False,
        detected_at=datetime.now(timezone.utc),
    )
    db_session.add(det1)
    db_session.commit()

    inc1 = service.correlate_detection(det1, flow=flow1, system_user_id=admin.id)
    assert inc1.severity == "MEDIUM"

    # 2. Second detection from same source IP (CRITICAL severity - DDoS)
    flow2 = NetworkFlow(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_ip=src_ip,
        destination_ip="10.0.0.1",
        protocol="TCP",
    )
    db_session.add(flow2)
    det2 = Detection(
        id=str(uuid.uuid4()),
        flow_id=flow2.id,
        model_version_id=mv.id,
        attack_type="DDoS",
        confidence=0.98,
        risk_score=94.0,
        severity="CRITICAL",
        is_anomaly=True,
        detected_at=datetime.now(timezone.utc),
    )
    db_session.add(det2)
    db_session.commit()

    inc2 = service.correlate_detection(det2, flow=flow2, system_user_id=admin.id)

    # Must be attached to the SAME incident, not create a duplicate
    assert inc2.id == inc1.id
    # Severity must be escalated to CRITICAL
    assert inc2.severity == "CRITICAL"
    assert len(inc2.detections) == 2
    assert len(inc2.events) >= 2


def test_incident_lifecycle_and_assignment(db_session: Session, correlation_fixture):
    admin, mv = correlation_fixture
    service = IncidentService(db_session)

    # Create incident
    inc = service.repo.create(
        title="Test Incident Lifecycle",
        severity="HIGH",
        status="OPEN",
        created_by=admin.id,
    )
    db_session.commit()

    # Update status to INVESTIGATING
    updated = service.update_status(
        inc.id, "INVESTIGATING", actor_id=admin.id, comment="Starting triage"
    )
    assert updated.status == "INVESTIGATING"

    # Assign analyst
    assigned = service.assign_incident(inc.id, analyst_id=admin.id, actor_id=admin.id)
    assert assigned.assigned_to == admin.id

    # Resolve incident
    resolved = service.update_status(inc.id, "RESOLVED", actor_id=admin.id)
    assert resolved.status == "RESOLVED"
    assert resolved.resolved_at is not None

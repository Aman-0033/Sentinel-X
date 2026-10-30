"""Unit tests for SQLAlchemy models, foreign keys, relationships, and check constraints."""

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.analyst_feedback import AnalystFeedback
from app.db.models.audit_log import AuditLog
from app.db.models.data_source import DataSource
from app.db.models.detection import Detection
from app.db.models.incident import Incident
from app.db.models.incident_detection import IncidentDetection
from app.db.models.incident_event import IncidentEvent
from app.db.models.model_version import ModelVersion
from app.db.models.network_flow import NetworkFlow
from app.db.models.report import Report
from app.db.models.role import Role
from app.db.models.threat_intel import ThreatIntelEnrichment
from app.db.models.user import User


@pytest.fixture
def db_session(app) -> Session:
    """Fixture yielding a clean database session for testing."""
    from app.db.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def test_create_all_13_models_and_verify_relationships(db_session: Session):
    """Verify all 13 models can be instantiated and all relationships resolve correctly."""
    now = datetime.now(timezone.utc)

    # 1. Role
    role = Role(name="TEST_ADMIN", description="Test administrator")
    db_session.add(role)
    db_session.flush()

    # 2. User
    user = User(
        role_id=role.id,
        email="analyst.test@sentinel.internal",
        password_hash="$2b$12$e8p2Nq1j112233445566778899aabbccddeeffgghhiijjkkllmmnn",
        full_name="Lead Analyst",
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    assert user.role.name == "TEST_ADMIN"
    assert len(role.users) == 1

    # 3. DataSource
    data_source = DataSource(
        name="Network Sensor Alpha",
        source_type="LIVE_COLLECTOR",
        description="Core switch tap",
        configuration={"interface": "eth0", "promiscuous": True},
        created_by=user.id,
    )
    db_session.add(data_source)
    db_session.flush()
    assert data_source.creator.id == user.id
    assert len(user.data_sources) == 1

    # 4. NetworkFlow
    flow = NetworkFlow(
        source_id=data_source.id,
        timestamp=now,
        source_ip="192.168.1.100",
        source_port=445,
        destination_ip="10.0.0.5",
        destination_port=52341,
        protocol="TCP",
        packets=15,
        bytes=1420,
        duration_ms=Decimal("120.5"),
        direction="INBOUND",
        raw_features={"flag_syn": 1, "flag_ack": 1},
    )
    db_session.add(flow)
    db_session.flush()
    assert flow.source.id == data_source.id
    assert len(data_source.flows) == 1

    # 5. ModelVersion
    model_version = ModelVersion(
        name="xgboost_intrusion_classifier",
        version="v1.0.0",
        algorithm="XGBoost",
        artifact_uri="/ml/artifacts/models/xgb_v1.joblib",
        feature_schema={"features": ["bytes", "packets", "duration_ms"]},
        metrics={"f1": 0.985, "accuracy": 0.991},
        checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="ACTIVE",
        trained_at=now,
        created_by=user.id,
    )
    db_session.add(model_version)
    db_session.flush()
    assert model_version.creator.id == user.id

    # 6. Detection
    detection = Detection(
        flow_id=flow.id,
        model_version_id=model_version.id,
        attack_type="DDoS_SYN_Flood",
        confidence=Decimal("0.9850"),
        anomaly_score=Decimal("0.85000"),
        risk_score=Decimal("94.50"),
        severity="CRITICAL",
        is_anomaly=True,
        explanation={"top_feature": "packets_per_sec", "importance": 0.42},
        detected_at=now,
    )
    db_session.add(detection)
    db_session.flush()
    assert detection.flow.id == flow.id
    assert detection.model_version.id == model_version.id
    assert len(flow.detections) == 1

    # 7. ThreatIntelEnrichment
    enrichment = ThreatIntelEnrichment(
        detection_id=detection.id,
        indicator_type="IP",
        indicator_value="192.168.1.100",
        provider="VIRUSTOTAL",
        reputation_score=Decimal("85.00"),
        verdict="MALICIOUS",
        country="US",
        asn=15169,
        response_data={"positives": 12, "total": 70},
    )
    db_session.add(enrichment)
    db_session.flush()
    assert enrichment.detection.id == detection.id
    assert len(detection.threat_intel_enrichments) == 1

    # 8. Incident
    incident = Incident(
        title="High Volume SYN Flood against Internal Server",
        description="Automated incident created from critical flow detection.",
        severity="CRITICAL",
        status="OPEN",
        assigned_to=user.id,
        created_by=user.id,
    )
    db_session.add(incident)
    db_session.flush()
    assert incident.assignee.id == user.id
    assert incident.creator.id == user.id

    # 9. IncidentDetection (M:N)
    incident_detection = IncidentDetection(
        incident_id=incident.id,
        detection_id=detection.id,
    )
    db_session.add(incident_detection)
    db_session.flush()
    assert len(incident.detection_associations) == 1
    assert incident.detection_associations[0].detection.id == detection.id

    # 10. IncidentEvent
    event = IncidentEvent(
        incident_id=incident.id,
        event_type="STATUS_CHANGED",
        message="Incident escalated to CRITICAL priority by SOC Lead",
        metadata_={"previous_status": "OPEN", "new_status": "INVESTIGATING"},
        actor_id=user.id,
    )
    db_session.add(event)
    db_session.flush()
    assert event.incident.id == incident.id
    assert event.actor.id == user.id
    assert len(incident.events) == 1

    # 11. AnalystFeedback
    feedback = AnalystFeedback(
        detection_id=detection.id,
        analyst_id=user.id,
        verdict="TRUE_POSITIVE",
        comment="Confirmed SYN flood pattern during morning shift.",
    )
    db_session.add(feedback)
    db_session.flush()
    assert feedback.detection.id == detection.id
    assert feedback.analyst.id == user.id
    assert len(detection.analyst_feedback) == 1

    # 12. AuditLog
    audit = AuditLog(
        user_id=user.id,
        action="INCIDENT_STATUS_UPDATE",
        resource_type="Incident",
        resource_id=incident.id,
        ip_address="127.0.0.1",
        user_agent="Sentinel-Console/1.0",
        metadata_={"incident_id": incident.id, "new_status": "INVESTIGATING"},
    )
    db_session.add(audit)
    db_session.flush()
    assert audit.user.id == user.id
    assert len(user.audit_logs) == 1

    # 13. Report
    report = Report(
        generated_by=user.id,
        incident_id=incident.id,
        period_start=now,
        period_end=now,
        format="PDF",
        file_path="/reports/generated/report_20261030.pdf",
        status="COMPLETED",
    )
    db_session.add(report)
    db_session.flush()
    assert report.generator.id == user.id
    assert report.incident.id == incident.id
    assert len(user.reports) == 1
    assert len(incident.reports) == 1

    db_session.commit()


def test_network_flows_invalid_port_check_constraint(db_session: Session):
    """Verify check constraint rejects port numbers outside 1-65535."""
    now = datetime.now(timezone.utc)
    invalid_flow = NetworkFlow(
        timestamp=now,
        source_ip="192.168.1.1",
        source_port=70000,  # Invalid (> 65535)
        destination_ip="10.0.0.1",
        destination_port=80,
    )
    db_session.add(invalid_flow)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_detections_invalid_confidence_check_constraint(db_session: Session):
    """Verify check constraint rejects confidence outside [0, 1]."""
    now = datetime.now(timezone.utc)

    # Need a flow and model_version
    flow = NetworkFlow(
        timestamp=now,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
    )
    model = ModelVersion(
        name="model_test_bounds",
        version="v1.0",
        algorithm="RF",
        artifact_uri="/uri",
        feature_schema={},
        metrics={},
        checksum="abc123",
        status="ACTIVE",
        trained_at=now,
    )
    db_session.add_all([flow, model])
    db_session.flush()

    invalid_det = Detection(
        flow_id=flow.id,
        model_version_id=model.id,
        attack_type="PortScan",
        confidence=Decimal("1.5000"),  # Invalid (> 1.0)
        risk_score=Decimal("50.00"),
        severity="MEDIUM",
        is_anomaly=False,
        detected_at=now,
    )
    db_session.add(invalid_det)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_detections_invalid_severity_check_constraint(db_session: Session):
    """Verify check constraint rejects invalid severity enum."""
    now = datetime.now(timezone.utc)
    flow = NetworkFlow(timestamp=now, source_ip="10.0.0.1", destination_ip="10.0.0.2")
    model = ModelVersion(
        name="model_test_sev",
        version="v1.0",
        algorithm="RF",
        artifact_uri="/uri",
        feature_schema={},
        metrics={},
        checksum="abc123",
        status="ACTIVE",
        trained_at=now,
    )
    db_session.add_all([flow, model])
    db_session.flush()

    invalid_det = Detection(
        flow_id=flow.id,
        model_version_id=model.id,
        attack_type="PortScan",
        confidence=Decimal("0.9000"),
        risk_score=Decimal("50.00"),
        severity="UNKNOWN_SEVERITY",  # Invalid
        is_anomaly=False,
        detected_at=now,
    )
    db_session.add(invalid_det)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_incidents_invalid_status_check_constraint(db_session: Session):
    """Verify check constraint rejects invalid incident status."""
    role = Role(name="ROLE_INC_TEST")
    db_session.add(role)
    db_session.flush()
    user = User(
        role_id=role.id,
        email="inc.test@sentinel.internal",
        password_hash="hash",
        full_name="User",
    )
    db_session.add(user)
    db_session.flush()

    invalid_incident = Incident(
        title="Test Incident",
        severity="HIGH",
        status="INVALID_STATUS",  # Invalid
        created_by=user.id,
    )
    db_session.add(invalid_incident)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

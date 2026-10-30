"""Integration tests for Demo Data Generator (Section 47)."""

import sys
from pathlib import Path

from sqlalchemy.orm import Session

# Add scripts directory to path
scripts_dir = Path(__file__).resolve().parents[3] / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from demo_data import seed_demo_data

from app.db.models.data_source import DataSource
from app.db.models.detection import Detection
from app.db.models.incident import Incident
from app.db.models.model_version import ModelVersion
from app.db.models.network_flow import NetworkFlow
from app.db.models.role import Role
from app.db.models.threat_intel import ThreatIntelEnrichment
from app.db.models.user import User


def test_seed_demo_data_populates_all_telemetry(db_session: Session):
    """Verify seed_demo_data populates roles, users, flows, detections, and incidents."""
    seed_demo_data(session=db_session)

    # 1. Verify roles
    roles = db_session.query(Role).all()
    role_names = {r.name for r in roles}
    assert {"ADMIN", "ANALYST", "VIEWER"}.issubset(role_names)

    # 2. Verify demo users
    admin_user = db_session.query(User).filter(User.email == "admin@sentinel.internal").first()
    analyst_user = db_session.query(User).filter(User.email == "analyst@sentinel.internal").first()
    viewer_user = db_session.query(User).filter(User.email == "viewer@sentinel.internal").first()

    assert admin_user is not None
    assert admin_user.role.name == "ADMIN"
    assert analyst_user is not None
    assert analyst_user.role.name == "ANALYST"
    assert viewer_user is not None
    assert viewer_user.role.name == "VIEWER"

    # 3. Verify data source
    sources = db_session.query(DataSource).all()
    assert len(sources) >= 1

    # 4. Verify model version
    active_models = db_session.query(ModelVersion).filter(ModelVersion.status == "ACTIVE").all()
    assert len(active_models) >= 1

    # 5. Verify network flows
    flows = db_session.query(NetworkFlow).all()
    assert len(flows) >= 10

    # 6. Verify detections and explanations
    detections = db_session.query(Detection).all()
    assert len(detections) >= 5
    for det in detections:
        assert det.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert det.confidence >= 0.0 and det.confidence <= 1.0

    # 7. Verify correlated incidents
    incidents = db_session.query(Incident).all()
    assert len(incidents) >= 1
    for inc in incidents:
        assert inc.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert inc.status in ["OPEN", "TRIAGED", "INVESTIGATING", "CONTAINED", "CLOSED"]

    # 8. Verify threat intel enrichments
    ti_entries = db_session.query(ThreatIntelEnrichment).all()
    assert len(ti_entries) >= 1


def test_seed_demo_data_is_idempotent(db_session: Session):
    """Verify running seed_demo_data repeatedly does not fail or duplicate singleton entities."""
    seed_demo_data(session=db_session)
    count_users = db_session.query(User).count()
    count_sources = db_session.query(DataSource).count()

    # Second pass
    seed_demo_data(session=db_session)
    assert db_session.query(User).count() == count_users
    assert db_session.query(DataSource).count() == count_sources

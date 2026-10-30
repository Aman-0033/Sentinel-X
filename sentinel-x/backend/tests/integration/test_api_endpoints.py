"""Integration tests for Sentinel-X REST and WebSocket API endpoints.

Covers:
- Dashboard KPIs, Trends, Attack Distribution, Top Sources (Section 16)
- Ingestion Batch & CSV Upload Quarantine Pipeline (Section 17)
- Detection Catalog, Detail, Analysis, and Analyst Feedback (Section 18)
- Incident Management, Creation, Status Update, and Timeline Events (Section 19)
- Threat Intelligence IP Lookup and SSRF Protection (Section 20)
- Model Version Catalog and Activation RBAC (Section 21)
- Report Generation and Catalog (Section 22)
- User Administration and RBAC Rejection (Section 25)
- Real-time Authenticated WebSocket Broadcast (Section 23)
"""

import io
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

# Add scripts directory to path for demo_data
scripts_dir = Path(__file__).resolve().parents[3] / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from demo_data import seed_demo_data

from app.core.security import create_access_token
from app.db.models.data_source import DataSource
from app.db.models.detection import Detection
from app.db.models.incident import Incident
from app.db.models.model_version import ModelVersion
from app.db.models.user import User


@pytest.fixture
def api_test_context(db_session: Session):
    """Seed demo data and prepare user authentication headers."""
    seed_demo_data(session=db_session)

    admin_user = db_session.query(User).filter(User.email == "admin@sentinel.internal").first()
    analyst_user = db_session.query(User).filter(User.email == "analyst@sentinel.internal").first()
    viewer_user = db_session.query(User).filter(User.email == "viewer@sentinel.internal").first()

    admin_token = create_access_token(user_id=admin_user.id, role="ADMIN", email=admin_user.email)
    analyst_token = create_access_token(
        user_id=analyst_user.id, role="ANALYST", email=analyst_user.email
    )
    viewer_token = create_access_token(
        user_id=viewer_user.id, role="VIEWER", email=viewer_user.email
    )

    return {
        "admin_user": admin_user,
        "analyst_user": analyst_user,
        "viewer_user": viewer_user,
        "admin_token": admin_token,
        "analyst_token": analyst_token,
        "viewer_token": viewer_token,
        "admin_headers": {"Authorization": f"Bearer {admin_token}"},
        "analyst_headers": {"Authorization": f"Bearer {analyst_token}"},
        "viewer_headers": {"Authorization": f"Bearer {viewer_token}"},
    }


# ==========================================
# 1. Dashboard Endpoints (Section 16)
# ==========================================


def test_dashboard_summary(client, api_test_context):
    """Verify GET /api/v1/dashboard/summary returns operational KPIs."""
    headers = api_test_context["viewer_headers"]
    response = client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200

    payload = response.json()
    assert "data" in payload
    data = payload["data"]
    assert "active_threats" in data
    assert "critical_threats" in data
    assert "open_incidents" in data
    assert "traffic_volume" in data
    assert "security_score" in data
    assert "meta" in payload
    assert "request_id" in payload["meta"]


def test_dashboard_trends(client, api_test_context):
    """Verify GET /api/v1/dashboard/trends returns time-series points."""
    headers = api_test_context["analyst_headers"]
    response = client.get("/api/v1/dashboard/trends?hours=24&interval=1h", headers=headers)
    assert response.status_code == 200

    payload = response.json()
    assert "data" in payload
    assert isinstance(payload["data"], list)


def test_dashboard_attack_distribution(client, api_test_context):
    """Verify GET /api/v1/dashboard/attack-distribution returns breakdown."""
    headers = api_test_context["analyst_headers"]
    response = client.get("/api/v1/dashboard/attack-distribution", headers=headers)
    assert response.status_code == 200

    payload = response.json()
    assert "data" in payload
    assert isinstance(payload["data"], list)
    if payload["data"]:
        assert "attack_type" in payload["data"][0]
        assert "count" in payload["data"][0]


def test_dashboard_top_sources(client, api_test_context):
    """Verify GET /api/v1/dashboard/top-sources returns top attacker IPs."""
    headers = api_test_context["viewer_headers"]
    response = client.get("/api/v1/dashboard/top-sources?limit=5", headers=headers)
    assert response.status_code == 200

    payload = response.json()
    assert "data" in payload
    assert isinstance(payload["data"], list)


# ==========================================
# 2. Ingestion Endpoints (Section 17)
# ==========================================


def test_ingest_flow_batch_analyst_success(client, api_test_context, db_session):
    """Verify POST /api/v1/ingestion/flows/batch accepts valid telemetry batch."""
    headers = api_test_context["analyst_headers"]
    source = db_session.query(DataSource).first()

    payload = {
        "source_id": source.id if source else None,
        "flows": [
            {
                "source_ip": "198.51.100.99",
                "destination_ip": "10.0.0.15",
                "source_port": 49152,
                "destination_port": 22,
                "protocol": "TCP",
                "packets": 50,
                "bytes": 3400,
                "duration_ms": 150.0,
            }
        ],
    }
    response = client.post("/api/v1/ingestion/flows/batch", json=payload, headers=headers)
    assert response.status_code == 200

    res_data = response.json()["data"]
    assert res_data["accepted"] == 1
    assert "job_id" in res_data


def test_ingest_flow_batch_viewer_forbidden(client, api_test_context):
    """Verify VIEWER role is rejected when attempting batch flow ingestion."""
    headers = api_test_context["viewer_headers"]
    payload = {
        "flows": [
            {
                "source_ip": "198.51.100.99",
                "destination_ip": "10.0.0.15",
                "source_port": 49152,
                "destination_port": 22,
                "protocol": "TCP",
                "packets": 5,
                "bytes": 340,
                "duration_ms": 10.0,
            }
        ]
    }
    response = client.post("/api/v1/ingestion/flows/batch", json=payload, headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_ingest_csv_upload_success(client, api_test_context):
    """Verify POST /api/v1/ingestion/upload safely quarantines and ingests CSV."""
    headers = api_test_context["analyst_headers"]
    csv_content = (
        "source_ip,destination_ip,source_port,destination_port,protocol,packets,bytes,duration_ms\n"
        "203.0.113.12,10.0.0.5,51234,443,TCP,20,1500,80.5\n"
    )
    files = {"file": ("test_flows.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}

    response = client.post("/api/v1/ingestion/upload", files=files, headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["status"] == "COMPLETED"
    assert data["accepted"] == 1


# ==========================================
# 3. Detection Endpoints (Section 18)
# ==========================================


def test_list_detections_pagination(client, api_test_context):
    """Verify GET /api/v1/detections supports pagination and Section 14 collection envelope."""
    headers = api_test_context["viewer_headers"]
    response = client.get("/api/v1/detections?page=1&page_size=5", headers=headers)
    assert response.status_code == 200

    payload = response.json()
    assert "data" in payload
    assert isinstance(payload["data"], list)
    assert len(payload["data"]) <= 5
    assert "meta" in payload
    assert payload["meta"]["page"] == 1
    assert payload["meta"]["page_size"] == 5
    assert payload["meta"]["total"] >= 5


def test_get_detection_detail(client, api_test_context, db_session):
    """Verify GET /api/v1/detections/{id} returns full detection telemetry and explanation."""
    headers = api_test_context["analyst_headers"]
    det = db_session.query(Detection).first()
    assert det is not None

    response = client.get(f"/api/v1/detections/{det.id}", headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["id"] == det.id
    assert data["attack_type"] == det.attack_type
    assert "explanation" in data
    assert "flow" in data


def test_analyst_feedback_submission(client, api_test_context, db_session):
    """Verify POST /api/v1/detections/{id}/feedback records verified analyst label."""
    headers = api_test_context["analyst_headers"]
    det = db_session.query(Detection).first()

    payload = {
        "verdict": "FALSE_POSITIVE",
        "comment": "Scheduled maintenance automated backup routine.",
    }
    response = client.post(f"/api/v1/detections/{det.id}/feedback", json=payload, headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["detection_id"] == det.id
    assert data["verdict"] == "FALSE_POSITIVE"
    assert data["comment"] == "Scheduled maintenance automated backup routine."


def test_feedback_viewer_forbidden(client, api_test_context, db_session):
    """Verify VIEWER role is blocked from submitting analyst feedback."""
    headers = api_test_context["viewer_headers"]
    det = db_session.query(Detection).first()

    payload = {"verdict": "TRUE_POSITIVE"}
    response = client.post(f"/api/v1/detections/{det.id}/feedback", json=payload, headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


# ==========================================
# 4. Incident Endpoints (Section 19)
# ==========================================


def test_list_incidents(client, api_test_context):
    """Verify GET /api/v1/incidents returns paginated incident records."""
    headers = api_test_context["viewer_headers"]
    response = client.get("/api/v1/incidents?page=1&page_size=10", headers=headers)
    assert response.status_code == 200

    payload = response.json()
    assert "data" in payload
    assert isinstance(payload["data"], list)
    assert len(payload["data"]) >= 1


def test_create_manual_incident(client, api_test_context):
    """Verify POST /api/v1/incidents creates a new incident by an analyst."""
    headers = api_test_context["analyst_headers"]
    payload = {
        "title": "Suspicious exfiltration on non-standard port",
        "description": "High entropy outbound connection to untrusted host.",
        "severity": "HIGH",
        "status": "OPEN",
    }
    response = client.post("/api/v1/incidents", json=payload, headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["title"] == payload["title"]
    assert data["severity"] == "HIGH"
    assert data["status"] == "OPEN"


def test_patch_incident_status(client, api_test_context, db_session):
    """Verify PATCH /api/v1/incidents/{id} transitions incident lifecycle."""
    headers = api_test_context["analyst_headers"]
    inc = db_session.query(Incident).first()

    payload = {"status": "CONTAINED", "notes": "Egress firewall rule applied."}
    response = client.patch(f"/api/v1/incidents/{inc.id}", json=payload, headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["id"] == inc.id
    assert data["status"] == "CONTAINED"


def test_create_incident_event(client, api_test_context, db_session):
    """Verify POST /api/v1/incidents/{id}/events appends an audit timeline entry."""
    headers = api_test_context["analyst_headers"]
    inc = db_session.query(Incident).first()

    payload = {
        "event_type": "CONTAINMENT_ACTION",
        "message": "Host isolated from internal subnet.",
    }
    response = client.post(f"/api/v1/incidents/{inc.id}/events", json=payload, headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["event_type"] == "CONTAINMENT_ACTION"
    assert data["message"] == "Host isolated from internal subnet."


# ==========================================
# 5. Threat Intelligence Endpoints (Section 20)
# ==========================================


def test_threat_intel_public_ip_lookup(client, api_test_context):
    """Verify GET /api/v1/threat-intel/ip/{ip} resolves threat reputation for public IP."""
    headers = api_test_context["analyst_headers"]
    response = client.get("/api/v1/threat-intel/ip/8.8.8.8", headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["indicator"] == "8.8.8.8"
    assert data["indicator_type"] == "ip"
    assert "reputation_score" in data
    assert "verdict" in data


def test_threat_intel_private_ip_rejected_ssrf(client, api_test_context):
    """Verify private and loopback IPs are strictly rejected by SSRF protection."""
    headers = api_test_context["analyst_headers"]
    for private_ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1"]:
        response = client.get(f"/api/v1/threat-intel/ip/{private_ip}", headers=headers)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# ==========================================
# 6. ML Model Registry Endpoints (Section 21)
# ==========================================


def test_list_models(client, api_test_context):
    """Verify GET /api/v1/models lists all registered models."""
    headers = api_test_context["viewer_headers"]
    response = client.get("/api/v1/models", headers=headers)
    assert response.status_code == 200

    payload = response.json()
    assert "data" in payload
    assert len(payload["data"]) >= 1


def test_activate_model_admin_success(client, api_test_context, db_session):
    """Verify POST /api/v1/models/{id}/activate succeeds for ADMIN."""
    headers = api_test_context["admin_headers"]
    model = db_session.query(ModelVersion).first()

    response = client.post(f"/api/v1/models/{model.id}/activate", headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["model_id"] == model.id
    assert data["status"] == "ACTIVE"


def test_activate_model_analyst_forbidden(client, api_test_context, db_session):
    """Verify POST /api/v1/models/{id}/activate is forbidden for ANALYST."""
    headers = api_test_context["analyst_headers"]
    model = db_session.query(ModelVersion).first()

    response = client.post(f"/api/v1/models/{model.id}/activate", headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


# ==========================================
# 7. Reports Endpoints (Section 22)
# ==========================================


def test_request_and_list_reports(client, api_test_context):
    """Verify POST /api/v1/reports requests a report and GET /api/v1/reports lists it."""
    headers = api_test_context["analyst_headers"]
    payload = {
        "period_start": "2026-10-01T00:00:00Z",
        "period_end": "2026-10-31T23:59:59Z",
        "format": "JSON",
    }
    create_res = client.post("/api/v1/reports", json=payload, headers=headers)
    assert create_res.status_code == 200

    report_id = create_res.json()["data"]["id"]

    list_res = client.get("/api/v1/reports", headers=headers)
    assert list_res.status_code == 200
    ids = [r["id"] for r in list_res.json()["data"]]
    assert report_id in ids


# ==========================================
# 8. User Management Endpoints (Section 25)
# ==========================================


def test_list_users_admin_only(client, api_test_context):
    """Verify GET /api/v1/users is restricted to ADMIN."""
    # ADMIN succeeds
    admin_res = client.get("/api/v1/users", headers=api_test_context["admin_headers"])
    assert admin_res.status_code == 200
    assert len(admin_res.json()["data"]) >= 3

    # ANALYST forbidden
    analyst_res = client.get("/api/v1/users", headers=api_test_context["analyst_headers"])
    assert analyst_res.status_code == 403
    assert analyst_res.json()["error"]["code"] == "AUTHORIZATION_DENIED"

    # VIEWER forbidden
    viewer_res = client.get("/api/v1/users", headers=api_test_context["viewer_headers"])
    assert viewer_res.status_code == 403
    assert viewer_res.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_create_user_admin_success(client, api_test_context):
    """Verify POST /api/v1/users allows ADMIN to provision a new user."""
    headers = api_test_context["admin_headers"]
    new_email = f"new_operator_{uuid.uuid4().hex[:6]}@sentinel.internal"
    payload = {
        "email": new_email,
        "password": "SecurePassword2026!",
        "full_name": "Tier 1 Triage Operator",
        "role": "ANALYST",
    }
    response = client.post("/api/v1/users", json=payload, headers=headers)
    assert response.status_code == 200

    data = response.json()["data"]
    assert data["email"] == new_email
    assert data["role"] == "ANALYST"
    assert data["full_name"] == "Tier 1 Triage Operator"


# ==========================================
# 9. Real-Time WebSocket Endpoint (Section 23)
# ==========================================


def test_websocket_authenticated_connection_and_heartbeat(client, api_test_context):
    """Verify WS /api/v1/ws/dashboard authenticates, receives welcome, and responds to PING."""
    token = api_test_context["analyst_token"]

    with client.websocket_connect(f"/api/v1/ws/dashboard?token={token}") as ws:
        # Receive welcome connection payload
        welcome = ws.receive_json()
        assert welcome["event"] == "CONNECTED"
        assert "Authenticated" in welcome["data"]["message"]

        # Send heartbeat PING
        ws.send_text("PING")
        pong = ws.receive_json()
        assert pong["event"] == "PONG"


def test_websocket_unauthenticated_connection_rejected(client):
    """Verify WebSocket handshake is rejected when token is missing or invalid."""
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws/dashboard") as ws:
            ws.receive_text()

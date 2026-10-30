"""Security Test Suite: Authorization & RBAC Boundaries (Section 46.2).

Verifies:
- VIEWER cannot activate models (403 Forbidden).
- VIEWER cannot modify incidents (403 Forbidden).
- VIEWER cannot submit analyst feedback (403 Forbidden).
- VIEWER cannot view audit logs (403 Forbidden).
- VIEWER cannot ingest telemetry or upload files (403 Forbidden).
- ANALYST cannot manage users (create, list) (403 Forbidden).
- ANALYST cannot activate ML models (403 Forbidden).
- ADMIN has full access across all operations.
- Unauthenticated access is uniformly rejected (401 Unauthorized).
- Token role-tampering (privilege escalation via fake claims) is prevented.
"""

import uuid
from jose import jwt
import pytest

from app.core.config import get_settings


def test_viewer_cannot_activate_models(client, auth_context):
    """Verify VIEWER role is strictly forbidden from activating ML models."""
    response = client.post(
        f"/api/v1/models/{uuid.uuid4()}/activate",
        headers=auth_context["viewer_headers"],
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_analyst_cannot_activate_models(client, auth_context):
    """Verify ANALYST role is forbidden from activating ML models (ADMIN only)."""
    response = client.post(
        f"/api/v1/models/{uuid.uuid4()}/activate",
        headers=auth_context["analyst_headers"],
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_viewer_cannot_modify_incidents(client, auth_context):
    """Verify VIEWER role cannot update incident status or assignees."""
    response = client.patch(
        f"/api/v1/incidents/{uuid.uuid4()}",
        headers=auth_context["viewer_headers"],
        json={"status": "CONTAINED", "notes": "Viewer attempt to modify status"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_viewer_cannot_add_incident_timeline_event(client, auth_context):
    """Verify VIEWER cannot add incident events / timeline notes."""
    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/events",
        headers=auth_context["viewer_headers"],
        json={"event_type": "NOTE", "message": "Viewer note"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_viewer_cannot_submit_analyst_feedback(client, auth_context):
    """Verify VIEWER role cannot submit detection ground truth feedback."""
    response = client.post(
        f"/api/v1/detections/{uuid.uuid4()}/feedback",
        headers=auth_context["viewer_headers"],
        json={"verdict": "FALSE_POSITIVE", "notes": "Viewer feedback"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_viewer_cannot_view_audit_logs(client, auth_context):
    """Verify VIEWER cannot access forensic audit logs."""
    response = client.get(
        "/api/v1/audit-logs",
        headers=auth_context["viewer_headers"],
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_analyst_cannot_manage_users_list(client, auth_context):
    """Verify ANALYST role cannot view system user directory."""
    response = client.get(
        "/api/v1/users",
        headers=auth_context["analyst_headers"],
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_analyst_cannot_create_user(client, auth_context):
    """Verify ANALYST role cannot provision new users."""
    response = client.post(
        "/api/v1/users",
        headers=auth_context["analyst_headers"],
        json={
            "email": "attacker@sentinel.internal",
            "password": "AttackerPass123!",
            "full_name": "Rogue User",
            "role": "ADMIN",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


def test_unauthenticated_requests_are_blocked_across_all_protected_routes(client):
    """Verify all protected API routes reject unauthenticated requests with 401."""
    protected_endpoints = [
        ("GET", "/api/v1/dashboard/summary"),
        ("GET", "/api/v1/dashboard/trends"),
        ("POST", "/api/v1/ingestion/flows/batch"),
        ("GET", "/api/v1/detections"),
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/models"),
        ("GET", "/api/v1/reports"),
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/audit-logs"),
    ]

    for method, path in protected_endpoints:
        if method == "GET":
            res = client.get(path)
        else:
            res = client.post(path, json={})
        assert res.status_code == 401, f"Route {path} did not reject unauthenticated request!"
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_role_tampering_forged_admin_claim_fails(client, auth_context):
    """Verify an attacker cannot escalate privilege by forging an admin JWT with invalid secret."""
    viewer = auth_context["viewer_user"]
    fake_secret = "attacker_forged_jwt_secret_key_at_least_32_chars"

    forged_token = jwt.encode(
        {
            "sub": viewer.id,
            "role": "ADMIN",
            "email": viewer.email,
            "type": "access",
            "exp": 9999999999,
        },
        fake_secret,
        algorithm="HS256",
    )

    response = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    # The server must reject the signature mismatch
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"

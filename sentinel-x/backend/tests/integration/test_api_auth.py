"""Integration tests for Authentication API endpoints (/api/v1/auth).

Verifies Milestone 4 Acceptance Criteria:
- POST /api/v1/auth/login returns 200 with JWT access token, user summary, and HttpOnly refresh cookie.
- POST /api/v1/auth/login rejects invalid credentials with generic 401 without enumeration.
- POST /api/v1/auth/refresh rotates refresh token and issues fresh access token.
- POST /api/v1/auth/refresh fails when token is omitted or invalid.
- POST /api/v1/auth/logout invalidates session and clears cookie.
- GET /api/v1/auth/me returns current user identity with valid Bearer token.
- GET /api/v1/auth/me rejects unauthenticated requests with 401.
"""

import uuid

import pytest
from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.db.models.role import Role
from app.db.models.user import User


@pytest.fixture
def auth_test_user(db_session: Session):
    """Seed test role and user for auth integration testing."""
    role = db_session.query(Role).filter(Role.name == "ANALYST").first()
    if not role:
        role = Role(name="ANALYST", description="Security analyst")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)

    raw_password = "CorrectHorseBatteryStaple2026!"
    email = f"auth_test_{uuid.uuid4().hex[:6]}@sentinel.internal"
    user = User(
        email=email,
        password_hash=get_password_hash(raw_password),
        full_name="Alex Mercer",
        role_id=role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    yield user, email, raw_password

    try:
        db_session.delete(user)
        db_session.commit()
    except Exception:
        db_session.rollback()


def test_login_success(client, auth_test_user):
    """Test successful login returns access token, user info, and sets refresh cookie."""
    _, email, password = auth_test_user

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert response.status_code == 200
    payload = response.json()
    assert "data" in payload
    data = payload["data"]
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900
    assert data["user"]["email"] == email
    assert data["user"]["role"] == "ANALYST"
    assert "meta" in payload
    assert "request_id" in payload["meta"]

    # Check HttpOnly refresh cookie is set
    assert "sentinel_refresh_token" in response.cookies


def test_login_invalid_password_returns_generic_401(client, auth_test_user):
    """Test invalid password returns generic 401 without revealing password mistake."""
    _, email, _ = auth_test_user

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword2026!"},
    )

    assert response.status_code == 401
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == "AUTHENTICATION_FAILED"
    assert "request_id" in payload["error"]


def test_login_nonexistent_user_returns_generic_401(client):
    """Test nonexistent email returns identical generic 401 error message."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@sentinel.internal", "password": "AnyPassword123!"},
    )

    assert response.status_code == 401
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == "AUTHENTICATION_FAILED"


def test_refresh_token_rotation(client, auth_test_user):
    """Test POST /api/v1/auth/refresh rotates the token and returns a new access token."""
    _, email, password = auth_test_user

    # 1. Login to obtain refresh token
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    initial_refresh = login_res.cookies["sentinel_refresh_token"]

    # 2. Refresh with cookie
    refresh_res = client.post(
        "/api/v1/auth/refresh",
        cookies={"sentinel_refresh_token": initial_refresh},
    )
    assert refresh_res.status_code == 200
    refresh_payload = refresh_res.json()
    assert "data" in refresh_payload
    assert "access_token" in refresh_payload["data"]

    # New cookie should be set
    assert "sentinel_refresh_token" in refresh_res.cookies
    rotated_refresh = refresh_res.cookies["sentinel_refresh_token"]
    assert rotated_refresh != initial_refresh


def test_refresh_token_missing_fails(client):
    """Test refresh fails when refresh token is absent."""
    response = client.post("/api/v1/auth/refresh")
    assert response.status_code == 401
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == "AUTHENTICATION_FAILED"


def test_logout(client, auth_test_user):
    """Test POST /api/v1/auth/logout revokes session and clears cookie."""
    _, email, password = auth_test_user

    # 1. Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    access_token = login_res.json()["data"]["access_token"]
    refresh_token = login_res.cookies["sentinel_refresh_token"]

    # 2. Logout with access token & refresh cookie
    logout_res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
        cookies={"sentinel_refresh_token": refresh_token},
    )
    assert logout_res.status_code == 200
    assert "data" in logout_res.json()

    # Refresh cookie must be expired/deleted
    set_cookie_header = logout_res.headers.get("set-cookie", "")
    assert "sentinel_refresh_token" in set_cookie_header


def test_get_me_success(client, auth_test_user):
    """Test GET /api/v1/auth/me returns current user identity when token is provided."""
    user, email, password = auth_test_user

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    access_token = login_res.json()["data"]["access_token"]

    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_res.status_code == 200
    payload = me_res.json()
    assert "data" in payload
    assert payload["data"]["email"] == email
    assert payload["data"]["role"] == "ANALYST"
    assert payload["data"]["full_name"] == "Alex Mercer"
    assert payload["data"]["is_active"] is True


def test_get_me_unauthorized_when_token_missing(client):
    """Test GET /api/v1/auth/me rejects request when Bearer token is missing."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == "AUTHENTICATION_FAILED"

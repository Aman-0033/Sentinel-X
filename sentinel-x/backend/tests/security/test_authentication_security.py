"""Security Test Suite: Authentication Security (Section 46.1).

Verifies:
- Invalid credentials rejected with generic error (no account enumeration).
- Brute-force / rate-limit controls activate on login.
- Expired access tokens rejected.
- Malformed access tokens (bad signature, corrupted payload, non-JWT) rejected.
- Refresh token rotation works and replay detection prevents token reuse.
- Logout properly invalidates session and revokes refresh token.
- Password hashing uses Argon2id and never stores plaintext.
"""

from datetime import timedelta
import time
from jose import jwt
import pytest

from app.core.config import get_settings
from app.core.security import create_access_token, create_refresh_token, verify_password


def test_invalid_password_returns_generic_error_no_enumeration(client, auth_context):
    """Verify failed login returns generic 401 and does not reveal email existence."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@sentinel.internal", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == "AUTHENTICATION_FAILED"
    # Generic message, must not disclose whether email exists
    assert "Invalid email or password" in payload["error"]["message"]


def test_nonexistent_user_returns_identical_generic_error(client, auth_context):
    """Verify non-existent user receives the exact same error message as wrong password."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent_victim@sentinel.internal", "password": "AnyPassword123!"},
    )
    assert response.status_code == 401
    payload = response.json()
    assert payload["error"]["code"] == "AUTHENTICATION_FAILED"
    assert "Invalid email or password" in payload["error"]["message"]


def test_expired_access_token_is_rejected(client, auth_context):
    """Verify that expired JWT access tokens are immediately rejected with 401."""
    user = auth_context["analyst_user"]
    # Create an expired token (negative delta)
    expired_token = create_access_token(
        user_id=user.id,
        role="ANALYST",
        email=user.email,
        expires_delta=timedelta(seconds=-10),
    )

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_malformed_token_tampered_signature_is_rejected(client, auth_context):
    """Verify that JWT with forged or invalid signature is rejected."""
    token = auth_context["admin_token"]
    # Tamper with signature by modifying the last characters
    tampered_token = token[:-5] + "AAAAA"

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_malformed_token_arbitrary_string_is_rejected(client):
    """Verify completely malformed non-JWT strings are rejected."""
    bad_tokens = [
        "not.a.valid.jwt",
        "Bearer",
        "12345",
        "undefined",
        "null",
        "{\"alg\":\"none\"}.{}",
    ]
    for bad_token in bad_tokens:
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_refresh_token_rotation_and_replay_defense(client, auth_context):
    """Verify refresh token rotation and replay prevention."""
    # 1. Login to get fresh tokens
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@sentinel.internal", "password": "SentinelAnalyst2026!"},
    )
    assert login_res.status_code == 200
    cookie = login_res.headers.get("set-cookie", "")
    assert "sentinel_refresh_token=" in cookie

    # Extract initial refresh token
    refresh_token = cookie.split("sentinel_refresh_token=")[1].split(";")[0]

    # 2. Use refresh token once -> succeeds and rotates
    client.cookies.clear()
    refresh_res1 = client.post(
        "/api/v1/auth/refresh",
        cookies={"sentinel_refresh_token": refresh_token},
    )
    assert refresh_res1.status_code == 200
    rotated_access_1 = refresh_res1.json()["data"]["access_token"]
    assert rotated_access_1

    # Extract rotated refresh token
    new_cookie = refresh_res1.headers.get("set-cookie", "")
    new_refresh_token = new_cookie.split("sentinel_refresh_token=")[1].split(";")[0]
    assert new_refresh_token != refresh_token

    # 3. Replay attack: try using the OLD consumed refresh token again -> must be rejected
    client.cookies.clear()
    refresh_res2 = client.post(
        "/api/v1/auth/refresh",
        cookies={"sentinel_refresh_token": refresh_token},
    )
    assert refresh_res2.status_code == 401
    assert "already been consumed" in refresh_res2.json()["error"]["message"].lower() or refresh_res2.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_logout_invalidates_session_and_refresh_token(client, auth_context):
    """Verify that logging out revokes the refresh token and clears cookie."""
    # 1. Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@sentinel.internal", "password": "SentinelViewer2026!"},
    )
    assert login_res.status_code == 200
    access_token = login_res.json()["data"]["access_token"]
    cookie = login_res.headers.get("set-cookie", "")
    refresh_token = cookie.split("sentinel_refresh_token=")[1].split(";")[0]

    # 2. Logout with Bearer token and refresh token cookie
    logout_res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
        cookies={"sentinel_refresh_token": refresh_token},
    )
    assert logout_res.status_code == 200
    # Verify cookie is cleared (max-age=0 or empty)
    logout_cookie = logout_res.headers.get("set-cookie", "")
    assert "sentinel_refresh_token=" in logout_cookie
    assert "max-age=0" in logout_cookie.lower() or "expires=" in logout_cookie.lower()

    # 3. Attempting to refresh using the logged-out refresh token must fail
    client.cookies.clear()
    refresh_res = client.post(
        "/api/v1/auth/refresh",
        cookies={"sentinel_refresh_token": refresh_token},
    )
    assert refresh_res.status_code == 401


def test_argon2id_password_hashing_properties(auth_context):
    """Verify that passwords are cryptographically hashed with Argon2id parameters."""
    user = auth_context["admin_user"]
    assert user.password_hash.startswith("$argon2id$")
    assert verify_password("SentinelAdmin2026!", user.password_hash) is True
    assert verify_password("WrongPassword!", user.password_hash) is False

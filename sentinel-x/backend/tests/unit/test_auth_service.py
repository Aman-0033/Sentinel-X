"""Unit tests for AuthService (Section 24)."""

import uuid

import pytest
from sqlalchemy.orm import Session

from app.core.exceptions import AuthenticationError, RateLimitError
from app.core.rate_limit import reset_rate_limit
from app.core.security import get_password_hash, verify_password
from app.db.models.role import Role
from app.db.models.user import User
from app.services.auth_service import AuthService


@pytest.fixture
def auth_fixture(app) -> tuple[Session, User, str]:
    from app.db.session import SessionLocal

    session = SessionLocal()
    role = session.query(Role).filter(Role.name == "ANALYST").first()
    if not role:
        role = Role(name="ANALYST", description="Analyst role")
        session.add(role)
        session.flush()

    raw_password = "SecurePassword123456!"
    user_email = f"analyst.auth.{uuid.uuid4().hex[:8]}@sentinel.internal"
    user = User(
        email=user_email,
        password_hash=get_password_hash(raw_password),
        full_name="SOC Lead Analyst",
        role_id=role.id,
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    yield session, user, raw_password

    try:
        session.delete(user)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def test_argon2id_password_hashing_and_verification():
    """Verify passwords are encrypted with Argon2id and can be verified."""
    pwd = "ComplexPassphrase2026!"
    hashed = get_password_hash(pwd)

    # Argon2id identifier
    assert hashed.startswith("$argon2id$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_authenticate_user_success(auth_fixture):
    """Verify authentication issues short-lived access and rotated refresh tokens."""
    session, user, raw_password = auth_fixture
    service = AuthService(session)
    ip = f"127.0.0.{uuid.uuid4().int % 200 + 10}"
    reset_rate_limit(f"login:{ip}")

    auth_user, access_token, refresh_token = service.authenticate_user(
        email=user.email,
        password=raw_password,
        client_ip=ip,
    )

    assert auth_user.id == user.id
    assert access_token is not None
    assert refresh_token is not None

    # Verify access token payload
    payload = service.validate_access_token(access_token)
    assert payload["sub"] == user.id
    assert payload["role"] == "ANALYST"
    assert payload["type"] == "access"
    assert "exp" in payload
    assert "jti" in payload


def test_authenticate_user_invalid_credentials_returns_generic_error(auth_fixture):
    """Verify generic error message to prevent account enumeration."""
    session, user, _ = auth_fixture
    service = AuthService(session)
    ip = f"127.0.0.{uuid.uuid4().int % 200 + 10}"
    reset_rate_limit(f"login:{ip}")

    # Wrong password
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_user(user.email, "WrongPassword123!", client_ip=ip)
    assert "Invalid email or password" in str(exc.value)

    # Non-existent email
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_user("ghost@sentinel.internal", "Password123!", client_ip=ip)
    assert "Invalid email or password" in str(exc.value)


def test_authenticate_user_login_rate_limit(auth_fixture):
    """Verify brute-force rate limit protection on login endpoint."""
    session, user, _ = auth_fixture
    service = AuthService(session)
    ip = "192.168.100.99"
    reset_rate_limit(f"login:{ip}")

    # Exhaust limit (5 per minute)
    for _ in range(5):
        try:
            service.authenticate_user(user.email, "WrongPassword123!", client_ip=ip)
        except AuthenticationError:
            pass

    # 6th attempt must trigger RateLimitError
    with pytest.raises(RateLimitError):
        service.authenticate_user(user.email, "WrongPassword123!", client_ip=ip)


def test_refresh_token_rotation_and_replay_protection(auth_fixture):
    """Verify 7-day refresh token rotation and reuse detection."""
    session, user, raw_password = auth_fixture
    service = AuthService(session)
    ip = f"127.0.0.{uuid.uuid4().int % 200 + 10}"
    reset_rate_limit(f"login:{ip}")

    _, access_token1, refresh_token1 = service.authenticate_user(
        user.email, raw_password, client_ip=ip
    )

    # 1. Rotate refresh token
    access_token2, refresh_token2 = service.refresh_tokens(refresh_token1)
    assert access_token2 != access_token1
    assert refresh_token2 != refresh_token1

    # 2. Attempting to reuse consumed refresh_token1 must fail (token replay)
    with pytest.raises(AuthenticationError) as exc:
        service.refresh_tokens(refresh_token1)
    assert "Refresh token has expired, been consumed, or was revoked" in str(exc.value)


def test_logout_and_token_revocation(auth_fixture):
    """Verify logout revokes refresh session and blacklists access token."""
    session, user, raw_password = auth_fixture
    service = AuthService(session)
    ip = f"127.0.0.{uuid.uuid4().int % 200 + 10}"
    reset_rate_limit(f"login:{ip}")

    _, access_token, refresh_token = service.authenticate_user(
        user.email, raw_password, client_ip=ip
    )

    # Logout
    service.logout(refresh_token_str=refresh_token, access_token_str=access_token)

    # Refresh must be rejected
    with pytest.raises(AuthenticationError):
        service.refresh_tokens(refresh_token)

    # Access token must be blacklisted
    with pytest.raises(AuthenticationError) as exc:
        service.validate_access_token(access_token)
    assert "revoked" in str(exc.value)


def test_revoke_all_user_sessions(auth_fixture):
    """Verify mid-lifetime session revocation (e.g. password change)."""
    session, user, raw_password = auth_fixture
    service = AuthService(session)
    ip = f"127.0.0.{uuid.uuid4().int % 200 + 10}"
    reset_rate_limit(f"login:{ip}")

    _, access_token, _ = service.authenticate_user(user.email, raw_password, client_ip=ip)

    # Mid-session security event
    service.revoke_all_user_sessions(user.id)

    # Access token must now be rejected
    with pytest.raises(AuthenticationError) as exc:
        service.validate_access_token(access_token)
    assert "session has been terminated" in str(exc.value)

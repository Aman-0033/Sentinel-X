"""Unit tests for role seeding and safe admin bootstrap scripts."""

import pytest
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.db.models.role import Role
from scripts.create_admin import create_or_update_admin
from scripts.seed_database import seed_roles


@pytest.fixture
def db_session(app) -> Session:
    from app.db.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def test_seed_roles_creates_default_roles_and_is_idempotent(db_session: Session):
    """Verify seed_roles inserts ADMIN, ANALYST, and VIEWER roles without duplicate errors."""
    seed_roles(db_session)

    roles = db_session.query(Role).all()
    role_names = {r.name for r in roles}
    assert "ADMIN" in role_names
    assert "ANALYST" in role_names
    assert "VIEWER" in role_names

    initial_count = len(roles)

    # Re-run to verify idempotency
    seed_roles(db_session)
    rechecked_roles = db_session.query(Role).all()
    assert len(rechecked_roles) == initial_count


def test_create_admin_creates_user_with_hashed_password(db_session: Session):
    """Verify create_or_update_admin creates admin with bcrypt password and ADMIN role."""
    admin_email = "bootstrap_admin@sentinel.internal"
    plain_password = "SuperSecureAdminPassword123!"

    user = create_or_update_admin(
        db=db_session,
        email=admin_email,
        password=plain_password,
        full_name="Bootstrap Administrator",
    )

    assert user.id is not None
    assert user.email == admin_email
    assert user.role.name == "ADMIN"
    assert user.is_active is True
    # Password must be hashed with bcrypt, never plaintext
    assert user.password_hash != plain_password
    assert user.password_hash.startswith("$2b$") or user.password_hash.startswith("$2a$")
    assert verify_password(plain_password, user.password_hash) is True

    # Re-run with same email returns existing user without errors (idempotent)
    re_user = create_or_update_admin(
        db=db_session,
        email=admin_email,
        password="DifferentPassword!",
    )
    assert re_user.id == user.id
    # Ensure existing password was preserved
    assert verify_password(plain_password, re_user.password_hash) is True


def test_create_admin_rejects_invalid_bootstrap_secret(db_session: Session):
    """Verify create_or_update_admin fails safely when bootstrap secret is incorrect."""
    with pytest.raises(PermissionError):
        create_or_update_admin(
            db=db_session,
            email="intruder@example.com",
            password="password",
            bootstrap_secret="wrong_unauthorized_secret",
        )

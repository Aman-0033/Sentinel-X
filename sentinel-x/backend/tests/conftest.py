"""Pytest Configuration and Fixtures for Sentinel-X."""

import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Configure test environment variables BEFORE importing application code
os.environ["ENVIRONMENT"] = "test"
os.environ["DEBUG"] = "true"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["CELERY_BROKER_URL"] = "redis://localhost:6379/0"
os.environ["CELERY_RESULT_BACKEND"] = "redis://localhost:6379/0"
os.environ["JWT_SECRET"] = "test_jwt_secret_for_testing_purposes_only_32_chars"
os.environ["JWT_REFRESH_SECRET"] = "test_jwt_refresh_secret_for_testing_32_chars"
os.environ["ADMIN_BOOTSTRAP_SECRET"] = "test_admin_bootstrap_secret_for_tests_32_chars"
os.environ["MODEL_SIGNING_KEY"] = "test_model_signing_key_for_testing_32_chars"
os.environ["CORS_ORIGINS"] = '["http://localhost:5173", "http://localhost:3000"]'

# Clear any cached settings
from app.core.config import get_settings

get_settings.cache_clear()

from app.db.base import Base
from app.db.session import engine
from app.main import create_app


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create all test database tables in SQLite in-memory database."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def app():
    """Create fresh application instance for testing."""
    return create_app()


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    """TestClient fixture with base URL."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_in_memory_rate_limits():
    """Reset rate limiting state between test cases to prevent test crosstalk."""
    from app.core.rate_limit import _in_memory_store

    _in_memory_store.clear()
    yield
    _in_memory_store.clear()


@pytest.fixture
def db_session(app) -> Generator:
    """Yield a database session for unit and service tests."""
    from app.db.session import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def auth_context(db_session):
    """Seed demo data and prepare user authentication tokens for all roles."""
    import sys
    from pathlib import Path
    scripts_dir = Path(__file__).resolve().parents[3] / "sentinel-x" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from demo_data import seed_demo_data
    from app.core.security import create_access_token
    from app.db.models.user import User

    seed_demo_data(session=db_session)
    admin_user = db_session.query(User).filter(User.email == "admin@sentinel.internal").first()
    analyst_user = db_session.query(User).filter(User.email == "analyst@sentinel.internal").first()
    viewer_user = db_session.query(User).filter(User.email == "viewer@sentinel.internal").first()

    admin_token = create_access_token(user_id=admin_user.id, role="ADMIN", email=admin_user.email)
    analyst_token = create_access_token(user_id=analyst_user.id, role="ANALYST", email=analyst_user.email)
    viewer_token = create_access_token(user_id=viewer_user.id, role="VIEWER", email=viewer_user.email)

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


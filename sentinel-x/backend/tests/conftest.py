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

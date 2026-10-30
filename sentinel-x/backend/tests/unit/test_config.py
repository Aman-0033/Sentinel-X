"""Unit tests for Pydantic application configuration.

Verifies:
- Safe failure when required configuration is missing.
- Strict security validation in production mode.
- Correct parsing of CORS origins, logging levels, and database URLs.
"""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_config_loads_with_valid_parameters():
    """Verify settings loads properly when all required parameters are provided."""
    settings = Settings(
        DATABASE_URL="postgresql+psycopg2://sentinel:pass@localhost:5432/sentinel_x",
        REDIS_URL="redis://localhost:6379/0",
        JWT_SECRET="secure_random_jwt_secret_with_32_chars_or_more",
        JWT_REFRESH_SECRET="secure_random_refresh_secret_with_32_chars_or_more",
        ADMIN_BOOTSTRAP_SECRET="secure_admin_bootstrap_secret_with_32_chars",
        MODEL_SIGNING_KEY="secure_model_signing_key_with_32_chars_or_more",
    )
    assert settings.PROJECT_NAME == "Sentinel-X"
    assert settings.VERSION == "1.0.0"
    assert settings.CELERY_BROKER_URL == "redis://localhost:6379/0"
    assert settings.CELERY_RESULT_BACKEND == "redis://localhost:6379/0"


def test_config_fails_safely_when_required_field_missing(monkeypatch):
    """Application must fail safely when required configuration is missing."""
    for env_var in [
        "DATABASE_URL",
        "REDIS_URL",
        "JWT_SECRET",
        "JWT_REFRESH_SECRET",
        "ADMIN_BOOTSTRAP_SECRET",
        "MODEL_SIGNING_KEY",
    ]:
        monkeypatch.delenv(env_var, raising=False)

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    errors = exc_info.value.errors()
    missing_fields = {e["loc"][0] for e in errors}
    assert "DATABASE_URL" in missing_fields
    assert "REDIS_URL" in missing_fields
    assert "JWT_SECRET" in missing_fields
    assert "JWT_REFRESH_SECRET" in missing_fields
    assert "ADMIN_BOOTSTRAP_SECRET" in missing_fields
    assert "MODEL_SIGNING_KEY" in missing_fields


def test_production_fails_if_debug_enabled():
    """Strict security check: production environment rejects DEBUG=True."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=True,
            DATABASE_URL="postgresql+psycopg2://sentinel:pass@localhost:5432/sentinel_x",
            REDIS_URL="redis://localhost:6379/0",
            JWT_SECRET="a" * 32,
            JWT_REFRESH_SECRET="b" * 32,
            ADMIN_BOOTSTRAP_SECRET="c" * 32,
            MODEL_SIGNING_KEY="d" * 32,
        )
    assert "DEBUG must not be True in production" in str(exc_info.value)


def test_production_fails_if_secrets_too_short():
    """Strict security check: production environment rejects secrets < 32 characters."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="postgresql+psycopg2://sentinel:pass@localhost:5432/sentinel_x",
            REDIS_URL="redis://localhost:6379/0",
            JWT_SECRET="short_secret",
            JWT_REFRESH_SECRET="b" * 32,
            ADMIN_BOOTSTRAP_SECRET="c" * 32,
            MODEL_SIGNING_KEY="d" * 32,
        )
    assert "JWT_SECRET must be at least 32 characters" in str(exc_info.value)


def test_production_fails_if_secret_contains_placeholder():
    """Strict security check: production rejects placeholder strings in secrets."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="postgresql+psycopg2://sentinel:pass@localhost:5432/sentinel_x",
            REDIS_URL="redis://localhost:6379/0",
            JWT_SECRET="replace_with_a_secure_random_key_that_is_32_characters",
            JWT_REFRESH_SECRET="b" * 32,
            ADMIN_BOOTSTRAP_SECRET="c" * 32,
            MODEL_SIGNING_KEY="d" * 32,
        )
    assert "contains placeholder/insecure keyword" in str(exc_info.value)


def test_production_fails_if_sqlite_database_used():
    """Strict security check: production rejects SQLite."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="sqlite:///test.db",
            REDIS_URL="redis://localhost:6379/0",
            JWT_SECRET="a" * 32,
            JWT_REFRESH_SECRET="b" * 32,
            ADMIN_BOOTSTRAP_SECRET="c" * 32,
            MODEL_SIGNING_KEY="d" * 32,
        )
    assert "Production cannot use SQLite" in str(exc_info.value)


def test_cors_origins_parsing_from_comma_separated_string():
    """Verify CORS_ORIGINS parser handles comma-separated string."""
    settings = Settings(
        DATABASE_URL="sqlite:///:memory:",
        REDIS_URL="redis://localhost:6379/0",
        JWT_SECRET="test_secret_for_unit_tests_32_characters_min_length",
        JWT_REFRESH_SECRET="test_refresh_secret_for_unit_tests_32_chars",
        ADMIN_BOOTSTRAP_SECRET="test_admin_bootstrap_secret_32_chars_long",
        MODEL_SIGNING_KEY="test_model_signing_key_32_chars_minimum",
        CORS_ORIGINS="https://soc.sentinel.internal, https://analyst.sentinel.internal",
    )
    assert "https://soc.sentinel.internal" in settings.CORS_ORIGINS
    assert "https://analyst.sentinel.internal" in settings.CORS_ORIGINS

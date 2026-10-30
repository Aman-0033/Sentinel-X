"""Unit tests for AuditService and log sanitization (Section 11.12 and Section 36)."""

import pytest
from sqlalchemy.orm import Session

from app.services.audit_service import AuditService


@pytest.fixture
def db_session(app) -> Session:
    from app.db.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def test_audit_service_logs_event_and_redacts_secrets(db_session: Session):
    """Verify audit log records events and redacts sensitive keys in metadata."""
    service = AuditService(db_session)

    metadata_with_secrets = {
        "action_details": "Admin rotated system secret",
        "password": "SuperSecretPassword123!",
        "jwt_secret": "my_jwt_signing_key_32_characters",
        "api_key": "VT_API_KEY_12345",
        "safe_counter": 100,
    }

    log_entry = service.log_event(
        action="ADMIN_SECRET_ROTATION",
        user_id="user-admin-uuid",
        resource_type="SystemConfig",
        ip_address="10.0.0.1",
        user_agent="Sentinel-Admin-CLI",
        metadata=metadata_with_secrets,
    )

    assert log_entry.id is not None
    assert log_entry.action == "ADMIN_SECRET_ROTATION"
    assert log_entry.user_id == "user-admin-uuid"

    # Verify redaction in stored metadata
    stored_meta = log_entry.metadata_
    assert stored_meta["action_details"] == "Admin rotated system secret"
    assert stored_meta["safe_counter"] == 100
    assert stored_meta["password"] == "[REDACTED]"
    assert stored_meta["jwt_secret"] == "[REDACTED]"
    assert stored_meta["api_key"] == "[REDACTED]"

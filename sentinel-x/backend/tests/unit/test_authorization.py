"""Unit tests for function-level and object-level RBAC authorization (Section 25)."""

import pytest

from app.core.authorization import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    authorize_action,
    has_function_permission,
    require_permission,
)
from app.core.exceptions import AuthorizationError
from app.db.models.incident import Incident
from app.db.models.role import Role
from app.db.models.user import User


@pytest.fixture
def admin_user():
    role = Role(name=ROLE_ADMIN)
    return User(id="user-admin-1", email="admin@sentinel.internal", role=role, is_active=True)


@pytest.fixture
def analyst_user():
    role = Role(name=ROLE_ANALYST)
    return User(id="user-analyst-1", email="analyst@sentinel.internal", role=role, is_active=True)


@pytest.fixture
def viewer_user():
    role = Role(name=ROLE_VIEWER)
    return User(id="user-viewer-1", email="viewer@sentinel.internal", role=role, is_active=True)


def test_function_level_permissions_matrix():
    """Verify Section 25 default permissions matrix across all three roles."""
    # Dashboard: all YES
    assert has_function_permission(ROLE_ADMIN, "dashboard:read") is True
    assert has_function_permission(ROLE_ANALYST, "dashboard:read") is True
    assert has_function_permission(ROLE_VIEWER, "dashboard:read") is True

    # Investigate incidents (read): all YES
    assert has_function_permission(ROLE_ADMIN, "incidents:read") is True
    assert has_function_permission(ROLE_ANALYST, "incidents:read") is True
    assert has_function_permission(ROLE_VIEWER, "incidents:read") is True

    # Modify incidents (write): ADMIN YES, ANALYST YES, VIEWER NO
    assert has_function_permission(ROLE_ADMIN, "incidents:write") is True
    assert has_function_permission(ROLE_ANALYST, "incidents:write") is True
    assert has_function_permission(ROLE_VIEWER, "incidents:write") is False

    # Analyst feedback: ADMIN YES, ANALYST YES, VIEWER NO
    assert has_function_permission(ROLE_ADMIN, "feedback:write") is True
    assert has_function_permission(ROLE_ANALYST, "feedback:write") is True
    assert has_function_permission(ROLE_VIEWER, "feedback:write") is False

    # Activate model: ADMIN YES, ANALYST NO, VIEWER NO
    assert has_function_permission(ROLE_ADMIN, "models:activate") is True
    assert has_function_permission(ROLE_ANALYST, "models:activate") is False
    assert has_function_permission(ROLE_VIEWER, "models:activate") is False

    # Manage users: ADMIN YES, ANALYST NO, VIEWER NO
    assert has_function_permission(ROLE_ADMIN, "users:write") is True
    assert has_function_permission(ROLE_ANALYST, "users:write") is False
    assert has_function_permission(ROLE_VIEWER, "users:write") is False

    # Audit logs: ADMIN YES, ANALYST YES, VIEWER NO
    assert has_function_permission(ROLE_ADMIN, "audit:read") is True
    assert has_function_permission(ROLE_ANALYST, "audit:read") is True
    assert has_function_permission(ROLE_VIEWER, "audit:read") is False


def test_object_level_incident_authorization(admin_user, analyst_user, viewer_user):
    """Verify object-level incident modification checks."""
    assigned_incident = Incident(
        id="inc-1",
        title="SYN Flood",
        severity="HIGH",
        status="OPEN",
        assigned_to=analyst_user.id,
        created_by="other-user",
    )
    unassigned_incident = Incident(
        id="inc-2",
        title="Port Scan",
        severity="LOW",
        status="OPEN",
        assigned_to=None,
        created_by="other-user",
    )
    other_incident = Incident(
        id="inc-3",
        title="Data Exfil",
        severity="CRITICAL",
        status="OPEN",
        assigned_to="someone-else",
        created_by="someone-else",
    )

    # Admin can modify any incident
    assert authorize_action(admin_user, "incidents:write", other_incident) is True

    # Analyst can modify assigned or unassigned incident
    assert authorize_action(analyst_user, "incidents:write", assigned_incident) is True
    assert authorize_action(analyst_user, "incidents:write", unassigned_incident) is True
    assert authorize_action(analyst_user, "incidents:write", other_incident) is False

    # Viewer cannot modify any incident
    assert authorize_action(viewer_user, "incidents:write", assigned_incident) is False


def test_require_permission_enforcement(analyst_user, viewer_user):
    """Verify require_permission raises AuthorizationError when access is unauthorized."""
    # Analyst cannot activate models
    with pytest.raises(AuthorizationError):
        require_permission(analyst_user, "models:activate")

    # Viewer cannot write incidents
    with pytest.raises(AuthorizationError):
        require_permission(viewer_user, "incidents:write")

    # Inactive user cannot do anything
    analyst_user.is_active = False
    with pytest.raises(AuthorizationError):
        require_permission(analyst_user, "dashboard:read")

"""Role-Based Access Control (RBAC) and Object-Level Authorization.

Strictly enforces Section 25 and Section 27-29 of architecture.md:
- Never trusts client-supplied roles.
- Enforces both function-level and object-level authorization policies.
"""

from typing import Any, Dict, Optional, Set

from app.core.exceptions import AuthorizationError
from app.db.models.incident import Incident
from app.db.models.user import User

# Role Names
ROLE_ADMIN = "ADMIN"
ROLE_ANALYST = "ANALYST"
ROLE_VIEWER = "VIEWER"

# Function-level Permission Matrix (Section 25)
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    ROLE_ADMIN: {
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "incidents:delete",
        "detections:read",
        "feedback:write",
        "models:read",
        "models:activate",
        "users:read",
        "users:write",
        "audit:read",
        "reports:read",
        "reports:write",
        "telemetry:ingest",
        "threat_intel:read",
    },
    ROLE_ANALYST: {
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "detections:read",
        "feedback:write",
        "models:read",
        "audit:read",
        "reports:read",
        "reports:write",
        "telemetry:ingest",
        "threat_intel:read",
    },
    ROLE_VIEWER: {
        "dashboard:read",
        "incidents:read",
        "detections:read",
        "models:read",
        "reports:read",
        "threat_intel:read",
    },
}


def get_user_role_name(user: User) -> str:
    """Safely extract role name from user entity."""
    if hasattr(user, "role") and user.role and hasattr(user.role, "name"):
        return user.role.name.upper()
    return getattr(user, "role_name", ROLE_VIEWER).upper()


def has_function_permission(role_name: str, action: str) -> bool:
    """Check if the given role has function-level permission for an action."""
    permissions = ROLE_PERMISSIONS.get(role_name.upper(), set())
    return action in permissions


has_permission = has_function_permission


def authorize_object_access(user: User, action: str, resource: Any) -> bool:
    """Evaluate object-level authorization for sensitive entities."""
    role_name = get_user_role_name(user)

    # Admins always have object-level clearance
    if role_name == ROLE_ADMIN:
        return True

    # User entity access: users can read/edit their own profile
    if isinstance(resource, User):
        if action in ("users:read_self", "users:update_self"):
            return resource.id == user.id
        return False

    # Incident entity access
    if isinstance(resource, Incident):
        if action == "incidents:read":
            return True  # Analysts and Viewers can read incidents
        if action == "incidents:write":
            if role_name == ROLE_ANALYST:
                # Analysts can update incidents assigned to them, unassigned incidents, or ones they created
                return resource.assigned_to in (None, user.id) or resource.created_by == user.id
            return False

    return True


def authorize_action(user: User, action: str, resource: Optional[Any] = None) -> bool:
    """Comprehensive authorization check combining function-level and object-level policies."""
    if not user or not user.is_active:
        return False

    role_name = get_user_role_name(user)

    # 1. Function-level permission check
    if not has_function_permission(role_name, action):
        return False

    # 2. Object-level permission check (if a specific resource instance was supplied)
    if resource is not None:
        if not authorize_object_access(user, action, resource):
            return False

    return True


def require_permission(user: User, action: str, resource: Optional[Any] = None) -> None:
    """Enforce authorization; raises AuthorizationError immediately if permission is denied."""
    if not authorize_action(user, action, resource):
        role_name = get_user_role_name(user)
        raise AuthorizationError(
            f"Action '{action}' is denied for role '{role_name}' on the requested resource."
        )

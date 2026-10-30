"""API Dependencies: Database sessions, JWT Authentication, RBAC, and Rate Limiting."""

from typing import Callable, Generator, List, Optional

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.authorization import ROLE_PERMISSIONS
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.logging import request_id_ctx
from app.core.rate_limit import enforce_rate_limit
from app.core.security import decode_access_token
from app.db.models.user import User
from app.db.session import SessionLocal
from app.repositories.users import UserRepository
from app.schemas.common import ResponseMeta

security_bearer = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_request_meta() -> ResponseMeta:
    """Extract current request_id for response meta envelope."""
    req_id = request_id_ctx.get()
    return ResponseMeta(request_id=req_id)


def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Authenticate incoming request using Bearer JWT access token."""
    if not auth or not auth.credentials:
        raise AuthenticationError("Authentication token is missing.")

    token = auth.credentials
    payload = decode_access_token(token)

    user_id = payload.get("sub")
    if not user_id:
        raise AuthenticationError("Invalid token payload: missing subject.")

    repo = UserRepository(db)
    user = repo.get_by_id(user_id)
    if not user:
        raise AuthenticationError("Authenticated user no longer exists.")

    if not user.is_active:
        raise AuthenticationError("User account is deactivated.")

    return user


def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    """Ensure user is active."""
    return user


class RoleChecker:
    """Dependency ensuring current user possesses one of the allowed RBAC roles."""

    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = [r.upper() for r in allowed_roles]

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        user_role = user.role.name.upper() if user.role else "VIEWER"
        if user_role not in self.allowed_roles:
            raise AuthorizationError(
                f"Role '{user_role}' is not authorized for this resource. Required: {self.allowed_roles}"
            )
        return user


class PermissionChecker:
    """Dependency verifying user possesses a specific fine-grained permission."""

    def __init__(self, permission: str):
        self.permission = permission

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        user_role = user.role.name.upper() if user.role else "VIEWER"
        allowed_perms = ROLE_PERMISSIONS.get(user_role, set())
        if self.permission not in allowed_perms:
            raise AuthorizationError(
                f"User does not possess required permission '{self.permission}'."
            )
        return user


def check_rate_limit(
    limit: int = 60,
    window_seconds: int = 60,
    key_prefix: str = "rate",
) -> Callable:
    """Dependency for endpoint-specific sliding-window rate limiting."""

    def _limiter(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        # Combine prefix and IP
        rate_key = f"{key_prefix}:{client_ip}"
        enforce_rate_limit(rate_key, limit=limit, window_seconds=window_seconds)

    return _limiter

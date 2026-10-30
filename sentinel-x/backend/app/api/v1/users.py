"""User Administration REST endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleChecker,
    get_current_user,
    get_db,
    get_request_meta,
)
from app.core.exceptions import AppValidationError, AuthorizationError, NotFoundError
from app.core.security import get_password_hash
from app.core.validation import validate_email, validate_password
from app.db.models.role import Role
from app.db.models.user import User
from app.repositories.users import UserRepository
from app.schemas.common import CollectionMeta, CollectionResponse, ResponseMeta, SuccessResponse
from app.schemas.user import UserCreateRequest, UserDetail, UserUpdateRequest

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "",
    response_model=CollectionResponse[UserDetail],
    dependencies=[Depends(RoleChecker(["ADMIN"]))],
    summary="List registered users (ADMIN only)",
)
def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    role: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> CollectionResponse[UserDetail]:
    """Retrieve paginated user list."""
    repo = UserRepository(db)
    skip = (page - 1) * page_size
    raw_users = repo.list_users(skip=skip, limit=page_size, role_name=role)
    total = repo.count_users(role_name=role)

    items = [
        UserDetail(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role.name if u.role else "VIEWER",
            is_active=u.is_active,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
        )
        for u in raw_users
    ]

    col_meta = CollectionMeta(
        page=page,
        page_size=page_size,
        total=total,
        request_id=meta.request_id,
    )
    return CollectionResponse(data=items, meta=col_meta)


@router.post(
    "",
    response_model=SuccessResponse[UserDetail],
    dependencies=[Depends(RoleChecker(["ADMIN"]))],
    summary="Create a new system user with RBAC role (ADMIN only)",
)
def create_user(
    req: UserCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[UserDetail]:
    """Register a new user account with Argon2id password hash."""
    clean_email = validate_email(req.email)
    validate_password(req.password)

    repo = UserRepository(db)
    existing = repo.get_by_email(clean_email)
    if existing:
        raise AppValidationError(f"User with email '{clean_email}' already exists.")

    role = db.query(Role).filter(Role.name == req.role.upper()).first()
    if not role:
        raise AppValidationError(f"Role '{req.role}' not found.")

    pwd_hash = get_password_hash(req.password)
    user = repo.create(
        email=clean_email,
        password_hash=pwd_hash,
        full_name=req.full_name.strip(),
        role_id=role.id,
        is_active=True,
    )

    data = UserDetail(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=role.name,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )
    return SuccessResponse(data=data, meta=meta)


@router.get(
    "/{user_id}",
    response_model=SuccessResponse[UserDetail],
    summary="Get user profile by ID",
)
def get_user_by_id(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[UserDetail]:
    """Retrieve user profile (caller must be ADMIN or target user)."""
    if current_user.role.name.upper() != "ADMIN" and current_user.id != user_id:
        raise AuthorizationError("You are not authorized to view this user profile.")

    repo = UserRepository(db)
    user = repo.get_by_id(user_id)
    if not user:
        raise NotFoundError(f"User '{user_id}' not found.")

    data = UserDetail(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.name if user.role else "VIEWER",
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )
    return SuccessResponse(data=data, meta=meta)


@router.patch(
    "/{user_id}",
    response_model=SuccessResponse[UserDetail],
    dependencies=[Depends(RoleChecker(["ADMIN"]))],
    summary="Update user details, status, or role (ADMIN only)",
)
def update_user(
    user_id: str,
    req: UserUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[UserDetail]:
    """Modify user state, role assignment, or active flag."""
    repo = UserRepository(db)
    user = repo.get_by_id(user_id)
    if not user:
        raise NotFoundError(f"User '{user_id}' not found.")

    update_kwargs = {}
    if req.full_name is not None:
        update_kwargs["full_name"] = req.full_name.strip()
    if req.is_active is not None:
        update_kwargs["is_active"] = req.is_active
    if req.role is not None:
        role = db.query(Role).filter(Role.name == req.role.upper()).first()
        if not role:
            raise AppValidationError(f"Role '{req.role}' not found.")
        update_kwargs["role_id"] = role.id

    updated = repo.update(user, **update_kwargs)
    data = UserDetail(
        id=updated.id,
        email=updated.email,
        full_name=updated.full_name,
        role=updated.role.name if updated.role else "VIEWER",
        is_active=updated.is_active,
        created_at=updated.created_at,
        last_login_at=updated.last_login_at,
    )
    return SuccessResponse(data=data, meta=meta)

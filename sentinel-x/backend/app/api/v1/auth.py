"""Authentication REST endpoints (Section 15)."""

from fastapi import APIRouter, Cookie, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import check_rate_limit, get_current_user, get_db, get_request_meta
from app.core.exceptions import AuthenticationError
from app.db.models.user import User
from app.schemas.auth import LoginData, LoginRequest, RefreshData, UserResponse, UserSummary
from app.schemas.common import ResponseMeta, SuccessResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=SuccessResponse[LoginData],
    dependencies=[Depends(check_rate_limit(limit=10, window_seconds=60, key_prefix="login"))],
    summary="Authenticate user and obtain access token",
)
def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[LoginData]:
    """Authenticate with email and password, returning 15-minute access token and setting 7-day HttpOnly cookie."""
    client_ip = request.client.host if request.client else "unknown"
    service = AuthService(db)

    user, access_token, refresh_token = service.authenticate_user(
        email=req.email,
        password=req.password,
        client_ip=client_ip,
    )

    # Set 7-day secure HttpOnly refresh token cookie
    response.set_cookie(
        key="sentinel_refresh_token",
        value=refresh_token,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in production over HTTPS
    )

    user_summary = UserSummary(
        id=user.id,
        email=user.email,
        name=user.full_name,
        role=user.role.name if user.role else "VIEWER",
    )

    return SuccessResponse(
        data=LoginData(
            access_token=access_token,
            token_type="bearer",
            expires_in=900,
            user=user_summary,
        ),
        meta=meta,
    )


@router.post(
    "/refresh",
    response_model=SuccessResponse[RefreshData],
    dependencies=[Depends(check_rate_limit(limit=30, window_seconds=60, key_prefix="refresh"))],
    summary="Rotate refresh token and issue fresh access token",
)
def refresh_token(
    request: Request,
    response: Response,
    sentinel_refresh_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[RefreshData]:
    """Consume existing refresh token, rotate it, and issue new credentials."""
    raw_token = sentinel_refresh_token or request.headers.get("x-refresh-token")
    if not raw_token:
        raise AuthenticationError("Refresh token missing.")

    client_ip = request.client.host if request.client else "unknown"
    service = AuthService(db)

    new_access, new_refresh = service.rotate_refresh_token(raw_token, client_ip=client_ip)

    # Update cookie with newly rotated refresh token
    response.set_cookie(
        key="sentinel_refresh_token",
        value=new_refresh,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=False,
    )

    return SuccessResponse(
        data=RefreshData(access_token=new_access, token_type="bearer", expires_in=900),
        meta=meta,
    )


@router.post(
    "/logout",
    response_model=SuccessResponse[dict],
    summary="Revoke refresh token and terminate session",
)
def logout(
    response: Response,
    sentinel_refresh_token: str | None = Cookie(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[dict]:
    """Revoke session and clear authentication cookies."""
    if sentinel_refresh_token:
        service = AuthService(db)
        service.logout_session(sentinel_refresh_token)

    response.delete_cookie(key="sentinel_refresh_token")
    return SuccessResponse(data={"message": "Logged out successfully."}, meta=meta)


@router.get(
    "/me",
    response_model=SuccessResponse[UserResponse],
    summary="Get authenticated user identity and role",
)
def get_me(
    current_user: User = Depends(get_current_user),
    meta: ResponseMeta = Depends(get_request_meta),
) -> SuccessResponse[UserResponse]:
    """Return the profile and role of the authenticated caller."""
    return SuccessResponse(
        data=UserResponse(
            id=current_user.id,
            email=current_user.email,
            full_name=current_user.full_name,
            role=current_user.role.name if current_user.role else "VIEWER",
            is_active=current_user.is_active,
            created_at=current_user.created_at,
            last_login_at=current_user.last_login_at,
        ),
        meta=meta,
    )

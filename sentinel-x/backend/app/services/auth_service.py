"""Authentication and Token Management Service.

Strictly implements Section 24 of architecture.md:
- Argon2id password verification and upgrade.
- Short-lived JWT access tokens (15 minutes).
- Rotated refresh tokens (7 days).
- Redis-backed session tracking and instant token revocation.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError
from app.core.rate_limit import enforce_rate_limit
from app.core.redis import get_redis_client
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    get_password_hash,
    verify_password,
)
from app.core.validation import validate_email
from app.db.models.user import User
from app.repositories.users import UserRepository

logger = logging.getLogger("sentinel.auth")

# In-memory session and revocation fallback store when Redis is unavailable/mocked
_in_memory_refresh_sessions: Dict[str, str] = {}  # jti -> user_id
_in_memory_blacklisted_jtis: Dict[str, float] = {}  # jti -> expire_timestamp
_in_memory_revoked_users: Dict[str, float] = {}  # user_id -> revocation_timestamp


class AuthService:
    """Service encapsulating identity verification, token lifecycle, and session security."""

    def __init__(self, db: Session, redis_client: Optional[object] = None) -> None:
        self.db = db
        self.user_repo = UserRepository(db)
        self.settings = get_settings()
        self._redis = redis_client

    def _get_redis(self):
        if self._redis is not None:
            return self._redis
        try:
            return get_redis_client()
        except Exception:
            return None

    def authenticate_user(
        self,
        email: str,
        password: str,
        client_ip: str = "unknown",
    ) -> Tuple[User, str, str]:
        """Authenticate user credentials and issue rotated access and refresh tokens.

        Returns:
            (user: User, access_token: str, refresh_token: str)
        """
        # 1. Enforce login rate limit against brute-force attacks (5 attempts/minute/IP)
        enforce_rate_limit(f"login:{client_ip}", limit=5, window_seconds=60)

        # 2. Syntax validation
        valid_email = validate_email(email)
        # Note: Do not reject short passwords on login to avoid revealing policy boundaries; validate structure
        if not password or not isinstance(password, str):
            raise AuthenticationError("Invalid email or password.")

        # 3. Lookup user
        user = self.user_repo.get_by_email(valid_email)
        if not user or not user.is_active:
            # Generic error message to prevent user enumeration (Section 24.4)
            raise AuthenticationError("Invalid email or password.")

        # 4. Verify password
        if not verify_password(password, user.password_hash):
            raise AuthenticationError("Invalid email or password.")

        # 5. Automatically upgrade legacy bcrypt hashes to modern Argon2id
        if not user.password_hash.startswith("$argon2"):
            user.password_hash = get_password_hash(password)

        # 6. Update last login timestamp
        user.last_login_at = datetime.now(timezone.utc)
        self.db.commit()

        # 7. Generate tokens
        role_name = user.role.name if user.role else "VIEWER"
        access_token = create_access_token(user_id=user.id, role=role_name, email=user.email)
        refresh_token, refresh_jti = create_refresh_token(user_id=user.id)

        # 8. Register active session in Redis
        self._register_refresh_session(refresh_jti, user.id)

        logger.info(
            f"User '{user.email}' authenticated successfully",
            extra={"action": "user_login", "user_id": user.id, "source_ip": client_ip},
        )
        return user, access_token, refresh_token

    def refresh_tokens(self, refresh_token_str: str) -> Tuple[str, str]:
        """Rotate consumed refresh token and issue fresh token pair.

        Enforces strict token rotation per Section 24.2.
        """
        if not refresh_token_str:
            raise AuthenticationError("Refresh token is required.")

        payload = decode_refresh_token(refresh_token_str)
        user_id = payload.get("sub")
        old_jti = payload.get("jti")

        if not user_id or not old_jti:
            raise AuthenticationError("Malformed refresh token.")

        # Verify refresh token is currently active
        if not self._is_refresh_session_active(old_jti, user_id):
            # Token reuse detected or token revoked! Invalidate all sessions as a defensive posture
            self.revoke_all_user_sessions(user_id)
            logger.warning(
                f"Suspicious refresh token reuse detected for user '{user_id}'. All sessions invalidated.",
                extra={"action": "token_reuse_detected", "user_id": user_id},
            )
            raise AuthenticationError("Refresh token has expired, been consumed, or was revoked.")

        # Consume old token (rotation)
        self._invalidate_refresh_session(old_jti)

        user = self.user_repo.get_by_id(user_id)
        if not user or not user.is_active:
            raise AuthenticationError("User account is inactive or no longer exists.")

        # Issue new token pair
        role_name = user.role.name if user.role else "VIEWER"
        new_access_token = create_access_token(user_id=user.id, role=role_name, email=user.email)
        new_refresh_token, new_jti = create_refresh_token(user_id=user.id)

        # Register new session
        self._register_refresh_session(new_jti, user.id)

        return new_access_token, new_refresh_token

    def rotate_refresh_token(
        self, refresh_token_str: str, client_ip: Optional[str] = None
    ) -> Tuple[str, str]:
        """Alias for refresh_tokens."""
        return self.refresh_tokens(refresh_token_str)

    def logout(
        self,
        refresh_token_str: Optional[str] = None,
        access_token_str: Optional[str] = None,
    ) -> None:
        """Invalidate server-side session and blacklist access token."""
        if refresh_token_str:
            try:
                payload = decode_refresh_token(refresh_token_str)
                jti = payload.get("jti")
                if jti:
                    self._invalidate_refresh_session(jti)
            except Exception:
                pass

        if access_token_str:
            try:
                payload = decode_access_token(access_token_str)
                jti = payload.get("jti")
                exp = payload.get("exp", time.time() + 900)
                if jti:
                    self._blacklist_access_token(jti, exp)
            except Exception:
                pass

    def logout_session(self, refresh_token_str: Optional[str] = None) -> None:
        """Alias for logout with refresh token."""
        self.logout(refresh_token_str=refresh_token_str)

    def validate_access_token(self, token_str: str) -> Dict[str, Any]:
        """Validate signature, expiry, and revocation state of an access token."""
        payload = decode_access_token(token_str)
        user_id = payload.get("sub")
        jti = payload.get("jti")
        iat = payload.get("iat", 0)

        # Check token blacklist
        if jti and self._is_token_blacklisted(jti):
            raise AuthenticationError("Access token has been revoked.")

        # Check user-level revocation marker
        if user_id and self._is_user_revoked_since(user_id, iat):
            raise AuthenticationError("User session has been terminated. Please log in again.")

        return payload

    def revoke_all_user_sessions(self, user_id: str) -> None:
        """Invalidate all active sessions for a user (e.g. password change)."""
        now = time.time()
        client = self._get_redis()
        if client:
            try:
                client.setex(
                    f"user_revoked:{user_id}",
                    self.settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
                    str(now),
                )
            except Exception:
                _in_memory_revoked_users[user_id] = now
        else:
            _in_memory_revoked_users[user_id] = now

    # ---------------- Session Storage Helpers ---------------- #

    def _register_refresh_session(self, jti: str, user_id: str) -> None:
        ttl = self.settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
        client = self._get_redis()
        if client:
            try:
                client.setex(f"session:{jti}", ttl, user_id)
                return
            except Exception:
                pass
        _in_memory_refresh_sessions[jti] = user_id

    def _is_refresh_session_active(self, jti: str, user_id: str) -> bool:
        client = self._get_redis()
        if client:
            try:
                stored = client.get(f"session:{jti}")
                return stored == user_id
            except Exception:
                pass
        return _in_memory_refresh_sessions.get(jti) == user_id

    def _invalidate_refresh_session(self, jti: str) -> None:
        client = self._get_redis()
        if client:
            try:
                client.delete(f"session:{jti}")
            except Exception:
                pass
        _in_memory_refresh_sessions.pop(jti, None)

    def _blacklist_access_token(self, jti: str, exp: float) -> None:
        remaining_ttl = max(1, int(exp - time.time()))
        client = self._get_redis()
        if client:
            try:
                client.setex(f"blacklist:{jti}", remaining_ttl, "revoked")
                return
            except Exception:
                pass
        _in_memory_blacklisted_jtis[jti] = exp

    def _is_token_blacklisted(self, jti: str) -> bool:
        client = self._get_redis()
        if client:
            try:
                return bool(client.exists(f"blacklist:{jti}"))
            except Exception:
                pass
        return jti in _in_memory_blacklisted_jtis and _in_memory_blacklisted_jtis[jti] > time.time()

    def _is_user_revoked_since(self, user_id: str, token_iat: float) -> bool:
        client = self._get_redis()
        revocation_ts = None
        if client:
            try:
                val = client.get(f"user_revoked:{user_id}")
                if val:
                    revocation_ts = float(val)
            except Exception:
                pass
        if revocation_ts is None:
            revocation_ts = _in_memory_revoked_users.get(user_id)

        return revocation_ts is not None and token_iat < revocation_ts

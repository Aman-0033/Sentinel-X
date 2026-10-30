"""Cryptographic Security, Password Hashing, and JWT Generation.

Strictly enforces Section 24 and Section 34 of architecture.md:
- Argon2id password hashing with recommended parameters.
- Backward compatibility for legacy bcrypt hashes.
- JWT access tokens (15-min) and refresh tokens (7-day).
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from jose import JWTError, jwt

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError

# Argon2id password hasher with recommended security parameters (Section 24.4)
argon2_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB memory
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def get_password_hash(password: str) -> str:
    """Generate an Argon2id cryptographic hash for a plaintext password."""
    return argon2_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plaintext password against an Argon2id or legacy bcrypt hash."""
    if not hashed_password or not plain_password:
        return False

    # Check for Argon2id hash ($argon2id$ or $argon2i$)
    if hashed_password.startswith("$argon2"):
        try:
            return argon2_hasher.verify(hashed_password, plain_password)
        except (VerifyMismatchError, InvalidHashError):
            return False

    # Fallback to bcrypt ($2a$, $2b$, $2y$)
    if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        try:
            return bcrypt.checkpw(pwd_bytes, hash_bytes)
        except Exception:
            return False

    return False


def create_access_token(
    user_id: str,
    role: str,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate a short-lived HMAC-signed JWT access token (default 15 minutes)."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

    payload: Dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "email": email,
        "type": "access",
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "iss": settings.PROJECT_NAME,
    }

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(
    user_id: str,
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, str]:
    """Generate a long-lived signed JWT refresh token (default 7 days).

    Returns:
        (refresh_token_jwt: str, jti: str)
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires = now + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    token_jti = uuid.uuid4().hex

    payload: Dict[str, Any] = {
        "sub": user_id,
        "jti": token_jti,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "iss": settings.PROJECT_NAME,
    }

    token = jwt.encode(payload, settings.JWT_REFRESH_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, token_jti


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token signature and expiration."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.PROJECT_NAME,
        )
        if payload.get("type") != "access":
            raise AuthenticationError("Invalid token type; expected access token.")
        return payload
    except JWTError as exc:
        raise AuthenticationError(f"Access token is invalid or expired: {str(exc)}") from exc


def decode_refresh_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT refresh token signature and expiration."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_REFRESH_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.PROJECT_NAME,
        )
        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid token type; expected refresh token.")
        return payload
    except JWTError as exc:
        raise AuthenticationError(f"Refresh token is invalid or expired: {str(exc)}") from exc

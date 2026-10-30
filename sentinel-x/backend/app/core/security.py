"""Cryptographic Security, Password Hashing, and Token Utilities.

Strictly enforces Section 2 (Principle 7: Never store plaintext passwords)
and Section 34 of architecture.md using modern native bcrypt.
"""

import bcrypt


def get_password_hash(password: str) -> str:
    """Generate a secure bcrypt hash for a plaintext password."""
    # Ensure UTF-8 encoded bytes, bound to bcrypt 72-byte max key limit
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Safely verify a plaintext password against a stored bcrypt hash."""
    pwd_bytes = plain_password.encode("utf-8")[:72]
    hash_bytes = hashed_password.encode("utf-8")
    try:
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False

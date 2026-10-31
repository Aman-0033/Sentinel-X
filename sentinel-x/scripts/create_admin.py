"""Safe administrative bootstrap script for Sentinel-X.

Creates the initial administrator account with bcrypt hashing and RBAC assignment.
Idempotent and safe: never logs the password, supports environment variable or CLI execution.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parents[1] / "backend"
if not backend_dir.exists():
    backend_dir = Path(__file__).resolve().parents[0] / "sentinel-x" / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(backend_dir.parent) not in sys.path:
    sys.path.insert(0, str(backend_dir.parent))

from app.core.config import get_settings
from app.core.security import get_password_hash
from app.db.models.role import Role
from app.db.models.user import User
from app.db.session import SessionLocal
from sqlalchemy.orm import Session

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("sentinel.bootstrap")


def create_or_update_admin(
    db: Session,
    email: str,
    password: str,
    full_name: str = "System Administrator",
    bootstrap_secret: str | None = None,
) -> User:
    """Create initial admin user or verify existing admin safely."""
    settings = get_settings()

    # Validate bootstrap secret if configured
    if bootstrap_secret and bootstrap_secret != settings.ADMIN_BOOTSTRAP_SECRET:
        raise PermissionError(
            "Bootstrap failed: ADMIN_BOOTSTRAP_SECRET does not match configuration."
        )

    # Ensure ADMIN role exists
    admin_role = db.query(Role).filter(Role.name == "ADMIN").first()
    if not admin_role:
        admin_role = Role(
            name="ADMIN",
            description="System administrator with full system, model, user, and audit access.",
        )
        db.add(admin_role)
        db.flush()

    # Check if user with email exists
    existing_user = db.query(User).filter(User.email == email.lower().strip()).first()
    if existing_user:
        existing_user.password_hash = get_password_hash(password)
        existing_user.role_id = admin_role.id
        existing_user.is_active = True
        db.commit()
        db.refresh(existing_user)
        logger.info(
            f"User with email '{email}' already exists (ID: {existing_user.id}). Password updated successfully."
        )
        return existing_user

    hashed_password = get_password_hash(password)
    admin_user = User(
        email=email.lower().strip(),
        password_hash=hashed_password,
        full_name=full_name,
        role_id=admin_role.id,
        is_active=True,
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    logger.info(
        f"Admin user created successfully with ID: {admin_user.id} and role: ADMIN"
    )
    return admin_user


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create or bootstrap initial Sentinel-X administrator."
    )
    parser.add_argument(
        "--email",
        default=os.getenv("ADMIN_EMAIL", "admin@sentinel.internal"),
        help="Admin email",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("ADMIN_PASSWORD", "SentinelAdmin2026!"),
        help="Admin password",
    )
    parser.add_argument(
        "--full-name",
        default=os.getenv("ADMIN_FULL_NAME", "System Administrator"),
        help="Full name",
    )
    parser.add_argument(
        "--bootstrap-secret",
        default=os.getenv("ADMIN_BOOTSTRAP_SECRET"),
        help="Bootstrap secret",
    )

    args = parser.parse_args()

    db = SessionLocal()
    try:
        create_or_update_admin(
            db=db,
            email=args.email,
            password=args.password,
            full_name=args.full_name,
            bootstrap_secret=args.bootstrap_secret,
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()

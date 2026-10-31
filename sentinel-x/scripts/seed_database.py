"""Seed default roles and static reference data into the Sentinel-X database.

Idempotent: safely executes without duplicating existing records.
"""

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

from app.db.models.role import Role
from app.db.session import SessionLocal
from sqlalchemy.orm import Session

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("sentinel.seed")

DEFAULT_ROLES = [
    {
        "name": "ADMIN",
        "description": "System administrator with full system, model, user, and audit access.",
    },
    {
        "name": "ANALYST",
        "description": "Security operations analyst with incident triage, detection inspection, and feedback permissions.",
    },
    {
        "name": "VIEWER",
        "description": "Read-only auditor with monitoring dashboard and report access.",
    },
]


def seed_roles(db: Session) -> None:
    """Seed the default RBAC roles if they do not already exist."""
    logger.info("Checking and seeding default roles...")
    for role_data in DEFAULT_ROLES:
        existing = db.query(Role).filter(Role.name == role_data["name"]).first()
        if not existing:
            role = Role(
                name=role_data["name"],
                description=role_data["description"],
            )
            db.add(role)
            logger.info(f"Created role: {role_data['name']}")
        else:
            logger.info(f"Role '{role_data['name']}' already exists.")

    db.commit()
    logger.info("Role seeding completed successfully.")


def main() -> None:
    db = SessionLocal()
    try:
        seed_roles(db)
    finally:
        db.close()


if __name__ == "__main__":
    main()

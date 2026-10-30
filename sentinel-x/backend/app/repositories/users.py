"""User and Role Repository.

Data access layer for User and Role entities.
"""

from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.models.role import Role
from app.db.models.user import User


class UserRepository:
    """Repository handling database operations for User and Role models."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, user_id: str) -> Optional[User]:
        """Fetch user by primary key ID."""
        return self.db.query(User).filter(User.id == user_id).first()

    def get_by_email(self, email: str) -> Optional[User]:
        """Fetch user by unique normalized email address."""
        return self.db.query(User).filter(User.email == email.lower().strip()).first()

    def list_users(
        self,
        skip: int = 0,
        limit: int = 50,
        is_active: Optional[bool] = None,
        role_name: Optional[str] = None,
    ) -> List[User]:
        """List users with optional pagination, active-status, and role filtering."""
        query = self.db.query(User)
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        if role_name:
            query = query.join(Role).filter(Role.name == role_name.upper())
        return query.order_by(User.created_at.desc()).offset(skip).limit(limit).all()

    def count_users(self, is_active: Optional[bool] = None, role_name: Optional[str] = None) -> int:
        """Count total matching users."""
        query = self.db.query(User)
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        if role_name:
            query = query.join(Role).filter(Role.name == role_name.upper())
        return query.count()

    def create(
        self,
        email: str,
        password_hash: str,
        full_name: str,
        role_id: str,
        is_active: bool = True,
    ) -> User:
        """Create and persist a new user record."""
        user = User(
            email=email.lower().strip(),
            password_hash=password_hash,
            full_name=full_name.strip(),
            role_id=role_id,
            is_active=is_active,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update(self, user: User, **kwargs) -> User:
        """Update user attributes safely."""
        for key, value in kwargs.items():
            if hasattr(user, key) and value is not None:
                setattr(user, key, value)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_role_by_name(self, role_name: str) -> Optional[Role]:
        """Fetch role by name (e.g. ADMIN, ANALYST, VIEWER)."""
        return self.db.query(Role).filter(Role.name == role_name.upper().strip()).first()

    def get_role_by_id(self, role_id: str) -> Optional[Role]:
        """Fetch role by primary key ID."""
        return self.db.query(Role).filter(Role.id == role_id).first()

    def list_roles(self) -> List[Role]:
        """List all available system roles."""
        return self.db.query(Role).order_by(Role.name).all()

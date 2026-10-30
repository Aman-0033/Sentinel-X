"""User and Role Management Schemas."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreateRequest(BaseModel):
    """Admin user creation payload."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=120)
    role: Literal["ADMIN", "ANALYST", "VIEWER"] = "ANALYST"


class UserUpdateRequest(BaseModel):
    """User modification payload."""

    model_config = ConfigDict(extra="forbid")

    full_name: Optional[str] = Field(None, min_length=2, max_length=120)
    is_active: Optional[bool] = None
    role: Optional[Literal["ADMIN", "ANALYST", "VIEWER"]] = None


class UserDetail(BaseModel):
    """User entity profile."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

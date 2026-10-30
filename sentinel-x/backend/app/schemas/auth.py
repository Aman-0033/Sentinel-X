"""Authentication and User Identity Schemas (Section 15)."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    """User login credential payload."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="Registered user email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class UserSummary(BaseModel):
    """Compact user profile representation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    name: str
    role: str


class LoginData(BaseModel):
    """Successful authentication token and user payload."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes
    user: UserSummary


class RefreshData(BaseModel):
    """Refreshed access token payload."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900


class UserResponse(BaseModel):
    """Full user profile response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

"""Audit Log Schemas (Section 11.12 & Section 25)."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class AuditLogItemSchema(BaseModel):
    """Schema for individual immutable audit log entry."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: datetime
    metadata: Optional[Dict[str, Any]] = None

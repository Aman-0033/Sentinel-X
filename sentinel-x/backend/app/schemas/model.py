"""Machine Learning Model Registry Schemas (Section 21)."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class ModelVersionItem(BaseModel):
    """Registered ML model metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    version: str
    algorithm: str
    artifact_uri: str
    status: str
    checksum: str
    feature_schema: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None
    trained_at: datetime
    created_at: datetime


class ModelActivateResponse(BaseModel):
    """Model activation confirmation."""

    id: str
    name: str
    version: str
    status: str = "ACTIVE"
    activated_at: datetime
    model_id: Optional[str] = None


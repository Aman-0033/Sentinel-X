"""Standard API Response Schemas and Envelopes.

Strictly enforces Section 14 of architecture.md:
- Success envelope: {"data": {...}, "meta": {"request_id": "..."}}
- Collection envelope: {"data": [...], "meta": {"page": 1, "page_size": 20, "total": 134, "request_id": "..."}}
- Error envelope: {"error": {"code": "...", "message": "...", "request_id": "..."}}
"""

from typing import Any, Generic, List, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ResponseMeta(BaseModel):
    """Metadata attached to standard API responses."""

    model_config = ConfigDict(extra="allow")

    request_id: Optional[str] = Field(default=None, description="Request correlation identifier")


class CollectionMeta(ResponseMeta):
    """Pagination metadata for list endpoints."""

    page: int = Field(default=1, ge=1, description="Current page index (1-based)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")
    total: int = Field(default=0, ge=0, description="Total count of items matching query")


class SuccessResponse(BaseModel, Generic[T]):
    """Standard success response envelope."""

    data: T
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


class CollectionResponse(BaseModel, Generic[T]):
    """Standard paginated collection response envelope."""

    data: List[T]
    meta: CollectionMeta


class ErrorDetail(BaseModel):
    """Safe client-facing error description."""

    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Safe human-readable error description")
    request_id: Optional[str] = Field(default=None, description="Request correlation identifier")
    details: Optional[Any] = Field(
        default=None, description="Optional safe validation/error details"
    )


class ErrorResponse(BaseModel):
    """Standard error response envelope."""

    error: ErrorDetail

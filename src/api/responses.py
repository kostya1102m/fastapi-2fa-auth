from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    status: str = "success"
    data: T
    meta: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Any = None


class ApiErrorResponse(BaseModel):
    status: str = "error"
    error: ErrorDetail
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class PaginatedData(BaseModel, Generic[T]):
    items: list[T]
    total: int
    offset: int
    limit: int
    has_more: bool
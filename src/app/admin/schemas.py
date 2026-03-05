from pydantic import BaseModel, Field

from src.core.constants import UserRole


class ChangeRoleRequest(BaseModel):
    role: UserRole = Field(description="New role for the user")


class AuditLogEntry(BaseModel):
    id: int
    actor_uid: str | None
    target_uid: str | None
    action: str
    details: dict | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    success: bool
    created_at: str

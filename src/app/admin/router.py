from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from src.api.responses import ApiResponse, PaginatedData
from src.app.admin.schemas import ChangeRoleRequest, AuditLogEntry
from src.app.auth.schemas import MessageResponse, UserResponse
from src.app.dependencies import (
    AdminUser,
    OwnerUser,
    get_admin_service,
)

from src.app.admin.service import AdminService

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get(
    "/users",
    response_model=ApiResponse[PaginatedData[UserResponse]],
    summary="List all users",
    description="Requires ADMIN or OWNER role.",
)
async def list_users(
    current_user: AdminUser,
    service: Annotated[AdminService, Depends(get_admin_service)],
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
):
    users, total = await service.list_users(offset=offset, limit=limit)
    return ApiResponse(
        data=PaginatedData(
            items=[UserResponse.model_validate(u) for u in users],
            total=total,
            offset=offset,
            limit=limit,
            has_more=(offset + limit) < total,
        )
    )


@router.get(
    "/users/{user_uid}",
    response_model=ApiResponse[UserResponse],
    summary="Get user by ID",
    description="Requires ADMIN or OWNER role.",
)
async def get_user(
    user_uid: UUID,
    current_user: AdminUser,
    service: Annotated[AdminService, Depends(get_admin_service)],
):
    user = await service.get_user(user_uid)
    return ApiResponse(data=UserResponse.model_validate(user))


@router.patch(
    "/users/{user_uid}/role",
    response_model=ApiResponse[UserResponse],
    summary="Change user role",
    description="Requires OWNER role. Cannot assign OWNER role.",
)
async def change_role(
    user_uid: UUID,
    data: ChangeRoleRequest,
    current_user: OwnerUser,
    service: Annotated[AdminService, Depends(get_admin_service)],
):
    user = await service.change_role(
        user_uid=user_uid,
        new_role=data.role,
        actor_uid=current_user.sub,
    )
    return ApiResponse(data=UserResponse.model_validate(user))


@router.delete(
    "/users/{user_uid}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user",
    description="Requires OWNER role. Cannot delete OWNER.",
)
async def delete_user(
    user_uid: UUID,
    current_user: OwnerUser,
    service: Annotated[AdminService, Depends(get_admin_service)],
):
    await service.delete_user(
        user_uid=user_uid,
        actor_uid=current_user.sub,
    )


@router.patch(
    "/users/{user_uid}/deactivate",
    response_model=ApiResponse[UserResponse],
    summary="Deactivate user (soft ban)",
    description="Requires ADMIN or OWNER role.",
)
async def deactivate_user(
    user_uid: UUID,
    current_user: AdminUser,
    service: Annotated[AdminService, Depends(get_admin_service)],
):
    user = await service.deactivate_user(user_uid)
    return ApiResponse(data=UserResponse.model_validate(user))


@router.patch(
    "/users/{user_uid}/activate",
    response_model=ApiResponse[UserResponse],
    summary="Activate user",
    description="Requires ADMIN or OWNER role.",
)
async def activate_user(
    user_uid: UUID,
    current_user: AdminUser,
    service: Annotated[AdminService, Depends(get_admin_service)],
):
    user = await service.activate_user(user_uid)
    return ApiResponse(data=UserResponse.model_validate(user))


@router.get(
    "/audit-log",
    response_model=ApiResponse[list[AuditLogEntry]],
    summary="View audit log",
    description="Requires ADMIN or OWNER role. "
                "Filter by user_uid or action.",
)
async def get_audit_log(
    current_user: AdminUser,
    service: Annotated[AdminService, Depends(get_admin_service)],
    user_uid: UUID | None = Query(default=None),
    action: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    entries = await service.get_audit_log(
        user_uid=user_uid,
        action=action,
        offset=offset,
        limit=limit,
    )
    return ApiResponse(
        data=[AuditLogEntry(**e) for e in entries]
    )
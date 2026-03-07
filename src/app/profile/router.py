from typing import Annotated

from fastapi import APIRouter, Depends, status

from src.api.responses import ApiResponse
from src.app.auth.schemas import MessageResponse, UserResponse
from src.app.dependencies import CurrentUser, get_profile_service
from src.app.profile.schemas import (
    ChangePasswordRequest,
    ChangePhoneRequest,
    ChangeUsernameRequest,
    Confirm2FARequest,
    Disable2FARequest,
    Enable2FAResponse,
)
from src.app.profile.service import ProfileService

router = APIRouter(prefix="/profile", tags=["Profile"])


@router.get(
    "/me",
    response_model=ApiResponse[UserResponse],
    summary="Get current user profile",
)
async def get_my_profile(
    current_user: CurrentUser,
    service: Annotated[ProfileService, Depends(get_profile_service)],
):
    user = await service.get_profile(current_user.sub)
    return ApiResponse(data=UserResponse.model_validate(user))


@router.patch(
    "/me/password",
    response_model=ApiResponse[MessageResponse],
    summary="Change password",
)
async def change_password(
    data: ChangePasswordRequest,
    current_user: CurrentUser,
    service: Annotated[ProfileService, Depends(get_profile_service)],
):
    await service.change_password(
        user_uid=current_user.sub,
        current_password=data.current_password,
        new_password=data.new_password,
    )
    return ApiResponse(
        data=MessageResponse(message="Password changed successfully")
    )


@router.patch(
    "/me/username",
    response_model=ApiResponse[UserResponse],
    summary="Change username",
)
async def change_username(
    data: ChangeUsernameRequest,
    current_user: CurrentUser,
    service: Annotated[ProfileService, Depends(get_profile_service)],
):
    user = await service.change_username(
        user_uid=current_user.sub,
        new_username=data.new_username,
    )
    return ApiResponse(data=UserResponse.model_validate(user))


@router.patch(
    "/me/phone",
    response_model=ApiResponse[UserResponse],
    summary="Change or remove phone number",
)
async def change_phone(
    data: ChangePhoneRequest,
    current_user: CurrentUser,
    service: Annotated[ProfileService, Depends(get_profile_service)],
):
    user = await service.change_phone(
        user_uid=current_user.sub,
        new_phone=data.new_phone_number,
    )
    return ApiResponse(data=UserResponse.model_validate(user))


@router.post(
    "/me/2fa/setup",
    response_model=ApiResponse[Enable2FAResponse],
    summary="Setup 2FA — Step 1: Get QR code",
    description="Generates TOTP secret and QR code. "
                "2FA is NOT enabled until confirmed with /2fa/confirm.",
)
async def setup_2fa(
    current_user: CurrentUser,
    service: Annotated[ProfileService, Depends(get_profile_service)],
):
    result = await service.setup_2fa(current_user.sub)
    return ApiResponse(data=Enable2FAResponse(**result))


@router.post(
    "/me/2fa/confirm",
    response_model=ApiResponse[MessageResponse],
    summary="Confirm 2FA — Step 2: Verify code",
    description="Verifies TOTP code from authenticator app. "
                "Enables 2FA if code is correct.",
)
async def confirm_2fa(
    data: Confirm2FARequest,
    current_user: CurrentUser,
    service: Annotated[ProfileService, Depends(get_profile_service)],
):
    await service.confirm_2fa(
        user_uid=current_user.sub,
        code=data.code,
    )
    return ApiResponse(
        data=MessageResponse(
            message="Two-factor authentication enabled successfully"
        )
    )


@router.post(
    "/me/2fa/disable",
    response_model=ApiResponse[MessageResponse],
    summary="Disable 2FA",
    description="Requires current TOTP code AND password for security.",
)
async def disable_2fa(
    data: Disable2FARequest,
    current_user: CurrentUser,
    service: Annotated[ProfileService, Depends(get_profile_service)],
):
    await service.disable_2fa(
        user_uid=current_user.sub,
        code=data.code,
        password=data.password,
    )
    return ApiResponse(
        data=MessageResponse(
            message="Two-factor authentication disabled successfully"
        )
    )
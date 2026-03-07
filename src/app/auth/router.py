from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from src.api.responses import ApiResponse
from src.app.auth.schemas import (
    EmailConfirmRequest,
    LoginRequest,
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    LogoutRequest,
    ActiveSessionResponse,
    LoginStep1Request,
    LoginStep2Request,
)
from src.app.auth.service import AuthService
from src.app.dependencies import CurrentUser, get_auth_service
from src.app.middleware.rate_limiter import (
    login_rate_limit,
    password_reset_rate_limit,
    register_rate_limit,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _get_user_agent(request: Request) -> str | None:
    ua = request.headers.get("User-Agent")
    return ua[:500] if ua else None


@router.post(
    "/register",
    response_model=ApiResponse[UserResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    dependencies=[Depends(register_rate_limit)],
)
async def register(
    data: RegisterRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    user = await service.register(
        username=data.username,
        email=data.email,
        password=data.password,
        phone_number=data.phone_number,
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(data=UserResponse.model_validate(user))


@router.post(
    "/login",
    response_model=ApiResponse[TokenResponse],
    summary="Authenticate user",
    dependencies=[Depends(login_rate_limit)],
)
async def login(
    data: LoginRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    tokens = await service.login(
        email=data.email,
        password=data.password,
        #totp_code=data.totp_code,
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(data=TokenResponse(**tokens))

@router.post(
    "/login/2fa",
    response_model=ApiResponse[TokenResponse],
    summary="Authenticate user via 2FA",
    dependencies=[Depends(login_rate_limit)],
)
async def login_2fa(
    data: LoginStep2Request,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    tokens = await service.login(
        email=data.email,
        password=data.password,
        totp_code=data.totp_code,
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(data=TokenResponse(**tokens))


@router.post(
    "/refresh",
    response_model=ApiResponse[TokenResponse],
    summary="Refresh tokens",
)
async def refresh_tokens(
    data: RefreshTokenRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    tokens = await service.refresh_tokens(
        refresh_token=data.refresh_token,
        ip_address=_get_client_ip(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(data=TokenResponse(**tokens))


@router.post(
    "/logout",
    response_model=ApiResponse[MessageResponse],
    summary="Logout current session",
    description="Revokes the refresh token for this session.",
)
async def logout(
    data: LogoutRequest,
    request: Request,
    current_user: CurrentUser,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    await service.logout(
        refresh_token=data.refresh_token,
        token_payload=current_user,
        ip_address=_get_client_ip(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(
        data=MessageResponse(message="Logged out successfully")
    )

@router.post(
    "/resend-confirmation",
    response_model=ApiResponse[MessageResponse],
    summary="Resend confirmation email",
    dependencies=[Depends(password_reset_rate_limit)],
)
async def resend_confirmation(
    data: PasswordResetRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    await service.resend_confirmation_email(
        email=data.email,
        ip_address=_get_client_ip(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(
        data=MessageResponse(
            message="If the email exists and is not yet confirmed, "
                    "a confirmation link has been sent",
        )
    )

@router.post(
    "/logout-all",
    response_model=ApiResponse[MessageResponse],
    summary="Logout from all devices",
    description="Revokes ALL refresh sessions for the current user.",
)
async def logout_all(
    request: Request,
    current_user: CurrentUser,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    await service.logout_all_devices(
        token_payload=current_user,
        ip_address=_get_client_ip(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(
        data=MessageResponse(
            message="Logged out from all devices successfully"
        )
    )


@router.get(
    "/sessions",
    response_model=ApiResponse[list[ActiveSessionResponse]],
    summary="List active sessions",
    description="Returns all active refresh sessions for the current user.",
)
async def list_sessions(
    current_user: CurrentUser,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    sessions = await service.get_active_sessions(current_user.sub)
    return ApiResponse(
        data=[ActiveSessionResponse(**s) for s in sessions],
    )


@router.post(
    "/email-confirm",
    response_model=ApiResponse[MessageResponse],
    summary="Confirm email address",
)
async def confirm_email(
    data: EmailConfirmRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    await service.confirm_email(
        token=data.token,
        ip_address=_get_client_ip(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(
        data=MessageResponse(message="Email confirmed successfully")
    )


@router.post(
    "/password-reset",
    response_model=ApiResponse[MessageResponse],
    summary="Request password reset",
    dependencies=[Depends(password_reset_rate_limit)],
)
async def request_password_reset(
    data: PasswordResetRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    await service.request_password_reset(
        email=data.email,
        ip_address=_get_client_ip(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(
        data=MessageResponse(
            message="If the email exists, a reset link has been sent"
        )
    )


@router.post(
    "/password-reset/confirm",
    response_model=ApiResponse[MessageResponse],
    summary="Confirm password reset",
)
async def confirm_password_reset(
    data: PasswordResetConfirm,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    await service.reset_password(
        token=data.token,
        new_password=data.new_password,
        ip_address=_get_client_ip(request),
        request_id=_get_request_id(request),
    )
    return ApiResponse(
        data=MessageResponse(message="Password reset successfully")
    )
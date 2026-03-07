import logging
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi import status
from sqlalchemy.exc import IntegrityError

from src.api.responses import ApiErrorResponse, ErrorDetail
from src.core.exceptions import (
    AccountNotActiveError,
    AppException,
    AuthenticationError,
    AuthorizationError,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    InvalidTokenError,
    PasswordValidationError,
    RateLimitExceededError,
    SamePasswordError,
    TokenError,
    TokenExpiredError,
    TokenRevokedException,
    TwoFactorAlreadyEnabledError,
    TwoFactorError,
    TwoFactorNotEnabledError,
    TwoFactorRequiredError,
    UserAlreadyExistsError,
    UserError,
    UserNotFoundError,
)

logger = logging.getLogger(__name__)

EXCEPTION_STATUS_MAP: dict[type[AppException], int] = {
    PasswordValidationError: status.HTTP_400_BAD_REQUEST,
    SamePasswordError: status.HTTP_400_BAD_REQUEST,
    TwoFactorAlreadyEnabledError: status.HTTP_400_BAD_REQUEST,
    TwoFactorNotEnabledError: status.HTTP_400_BAD_REQUEST,

    InvalidCredentialsError: 401,
    AccountNotActiveError: 401,
    TokenExpiredError: 401,
    InvalidTokenError: 401,
    TokenRevokedException: 401,
    TwoFactorRequiredError: 401,

    AuthorizationError: 403,
    InsufficientPermissionsError: 403,

    UserNotFoundError: 404,

    UserAlreadyExistsError: 409,

    RateLimitExceededError: 429,
}


def _get_error_code(exc: AppException) -> str:
    return type(exc).__name__


def _get_status_code(exc: AppException) -> int:
    if type(exc) in EXCEPTION_STATUS_MAP:
        return EXCEPTION_STATUS_MAP[type(exc)]

    for exc_type, status_code in EXCEPTION_STATUS_MAP.items():
        if isinstance(exc, exc_type):
            return status_code

    if isinstance(exc, AuthenticationError):
        return 401
    if isinstance(exc, AuthorizationError):
        return 403
    if isinstance(exc, TokenError):
        return 401
    if isinstance(exc, UserError):
        return 400
    if isinstance(exc, TwoFactorError):
        return 400

    return 500


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppException)
    async def app_exception_handler(
        request: Request, exc: AppException,
    ) -> JSONResponse:
        status_code = _get_status_code(exc)
        request_id = getattr(request.state, "request_id", str(uuid4()))

        log_data = {
            "request_id": request_id,
            "error": type(exc).__name__,
            "message": exc.message,
            "path": str(request.url.path),
            "method": request.method,
        }

        if status_code >= 500:
            logger.error(log_data, exc_info=True)
        else:
            logger.warning(log_data)

        response = ApiErrorResponse(
            error=ErrorDetail(
                code=_get_error_code(exc),
                message=exc.message,
                details=exc.details,
            )
        )

        headers = {}
        if isinstance(exc, RateLimitExceededError):
            headers["Retry-After"] = str(exc.retry_after)

        return JSONResponse(
            status_code=status_code,
            content=response.model_dump(mode="json"),
            headers=headers,
        )

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(
        request: Request, exc: IntegrityError,
    ) -> JSONResponse:
        logger.warning(
            {
                "error": "IntegrityError",
                "path": str(request.url.path),
                "detail": str(exc.orig) if exc.orig else str(exc),
            }
        )
        response = ApiErrorResponse(
            error=ErrorDetail(
                code="ConflictError",
                message="Resource already exists or conflicts "
                        "with existing data",
            )
        )
        return JSONResponse(
            status_code=409,
            content=response.model_dump(mode="json"),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception,
    ) -> JSONResponse:
        request_id = getattr(request.state, "request_id", str(uuid4()))
        logger.critical(
            {
                "request_id": request_id,
                "error": type(exc).__name__,
                "path": str(request.url.path),
                "method": request.method,
            },
            exc_info=True,
        )
        response = ApiErrorResponse(
            error=ErrorDetail(
                code="InternalServerError",
                message="An unexpected error occurred",
            )
        )
        return JSONResponse(
            status_code=500,
            content=response.model_dump(mode="json"),
        )
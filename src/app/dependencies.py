import logging
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.core.constants import UserRole
from src.core.exceptions import InsufficientPermissionsError
from src.core.protocols import (
    EmailServiceProtocol,
    PasswordHasherProtocol,
    RateLimiterProtocol,
    TokenServiceProtocol,
    TOTPServiceProtocol,
    UnitOfWorkProtocol,
    URLSafeTokenServiceProtocol,
)
from src.core.security import URLSafeTokenService
from src.domain.entities import TokenPayload
from src.external.database.unit_of_work import SQLAlchemyUnitOfWork
from src.external.email.email_service import EmailService
from src.external.rate_limiter.memory import InMemoryRateLimiter
from src.external.security.jwt_service import JWTService
from src.external.security.pwd_hasher import Argon2PasswordHasher
from src.external.security.totp_service import TOTPService

from src.app.admin.service import AdminService
from src.app.auth.service import AuthService
from src.app.profile.service import ProfileService

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=True)

_rate_limiter = InMemoryRateLimiter()

@lru_cache(maxsize=1)
def get_password_hasher() -> PasswordHasherProtocol:
    return Argon2PasswordHasher()


@lru_cache(maxsize=1)
def get_token_service() -> TokenServiceProtocol:
    return JWTService()


@lru_cache(maxsize=1)
def get_url_token_service() -> URLSafeTokenServiceProtocol:
    return URLSafeTokenService()


@lru_cache(maxsize=1)
def get_totp_service() -> TOTPServiceProtocol:
    return TOTPService()


@lru_cache(maxsize=1)
def get_email_service() -> EmailServiceProtocol:
    return EmailService()


def get_rate_limiter() -> RateLimiterProtocol:
    return _rate_limiter


def get_uow() -> UnitOfWorkProtocol:
    return SQLAlchemyUnitOfWork()


def get_auth_service(
    uow: Annotated[UnitOfWorkProtocol, Depends(get_uow)],
    hasher: Annotated[
        PasswordHasherProtocol, Depends(get_password_hasher)
    ],
    token_service: Annotated[
        TokenServiceProtocol, Depends(get_token_service)
    ],
    url_token_service: Annotated[
        URLSafeTokenServiceProtocol, Depends(get_url_token_service)
    ],
    totp_service: Annotated[
        TOTPServiceProtocol, Depends(get_totp_service)
    ],
    email_service: Annotated[
        EmailServiceProtocol, Depends(get_email_service)
    ],
) -> AuthService:
    return AuthService(
        uow=uow,
        hasher=hasher,
        token_service=token_service,
        url_token_service=url_token_service,
        totp_service=totp_service,
        email_service=email_service,
    )


def get_profile_service(
    uow: Annotated[UnitOfWorkProtocol, Depends(get_uow)],
    hasher: Annotated[
        PasswordHasherProtocol, Depends(get_password_hasher)
    ],
    totp_service: Annotated[
        TOTPServiceProtocol, Depends(get_totp_service)
    ],
) -> ProfileService:
    return ProfileService(
        uow=uow,
        hasher=hasher,
        totp_service=totp_service,
    )


def get_admin_service(
    uow: Annotated[UnitOfWorkProtocol, Depends(get_uow)],
) -> AdminService:
    return AdminService(uow=uow)


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials, Depends(_bearer_scheme)
    ],
    token_service: Annotated[
        TokenServiceProtocol, Depends(get_token_service)
    ],
) -> TokenPayload:
    return token_service.decode_access_token(credentials.credentials)


def require_role(*roles: UserRole):
    async def _check_role(
        current_user: Annotated[
            TokenPayload, Depends(get_current_user)
        ],
    ) -> TokenPayload:
        try:
            user_role = UserRole(current_user.role)
        except ValueError:
            raise InsufficientPermissionsError()

        if user_role not in roles:
            raise InsufficientPermissionsError(
                required_role=", ".join(r.value for r in roles),
            )
        return current_user

    return _check_role


CurrentUser = Annotated[TokenPayload, Depends(get_current_user)]
AdminUser = Annotated[
    TokenPayload,
    Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
]
OwnerUser = Annotated[
    TokenPayload,
    Depends(require_role(UserRole.OWNER)),
]
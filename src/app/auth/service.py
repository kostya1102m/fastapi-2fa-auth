import logging
from datetime import datetime, timezone

from src.config import settings
from src.core.constants import AuditAction, TokenPurpose
from src.core.exceptions import (
    AccountNotActiveError,
    InvalidCredentialsError,
    InvalidTokenError,
    InvalidTwoFactorCodeError,
    TokenExpiredError,
    TokenRevokedException,
    TwoFactorRequiredError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from src.core.protocols import (
    EmailServiceProtocol,
    PasswordHasherProtocol,
    TokenServiceProtocol,
    TOTPServiceProtocol,
    UnitOfWorkProtocol,
    URLSafeTokenServiceProtocol,
)
from src.domain.entities import TokenPayload, UserEntity
from src.external.security.refresh_token_service import (
    RefreshTokenService,
)

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(
        self,
        uow: UnitOfWorkProtocol,
        hasher: PasswordHasherProtocol,
        token_service: TokenServiceProtocol,
        url_token_service: URLSafeTokenServiceProtocol,
        totp_service: TOTPServiceProtocol,
        email_service: EmailServiceProtocol,
    ):
        self._uow = uow
        self._hasher = hasher
        self._tokens = token_service 
        self._url_tokens = url_token_service
        self._totp = totp_service
        self._email = email_service
        self._refresh = RefreshTokenService()

    async def register(
        self,
        username: str,
        email: str,
        password: str,
        phone_number: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> UserEntity:
        async with self._uow:
            if await self._uow.users.exists_by_email(email):
                raise UserAlreadyExistsError(field="email")
            if await self._uow.users.exists_by_username(username):
                raise UserAlreadyExistsError(field="username")
            if phone_number and await self._uow.users.exists_by_phone(
                phone_number
            ):
                raise UserAlreadyExistsError(field="phone number")

            user = UserEntity(
                username=username,
                email=email,
                password_hash=self._hasher.hash(password),
                phone_number=phone_number,
                is_active=False,
            )
            created_user = await self._uow.users.create(user)

            await self._uow.audit.log(
                action=AuditAction.USER_REGISTERED.value,
                actor_uid=created_user.uid,
                target_uid=created_user.uid,
                details={"username": username},
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            await self._uow.commit()

            await self._send_confirmation_email(created_user)
            return created_user

    async def login(
        self,
        email: str,
        password: str,
        totp_code: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        async with self._uow:
            user = await self._uow.users.get_by_email(email)

            if user is None:
                self._hasher.hash("dummy_password_for_timing")
                await self._uow.audit.log(
                    action=AuditAction.USER_LOGIN_FAILED.value,
                    details={"reason": "user_not_found"},
                    ip_address=ip_address,
                    user_agent=user_agent,
                    request_id=request_id,
                    success=False,
                )
                await self._uow.commit()
                raise InvalidCredentialsError()

            if not self._hasher.verify(password, user.password_hash):
                await self._uow.audit.log(
                    action=AuditAction.USER_LOGIN_FAILED.value,
                    actor_uid=user.uid,
                    details={"reason": "invalid_password"},
                    ip_address=ip_address,
                    user_agent=user_agent,
                    request_id=request_id,
                    success=False,
                )
                await self._uow.commit()
                raise InvalidCredentialsError()

            if not user.is_email_verified:
                await self._uow.audit.log(
                    action=AuditAction.USER_LOGIN_FAILED.value,
                    actor_uid=user.uid,
                    details={"reason": "email_not_verified"},
                    ip_address=ip_address,
                    user_agent=user_agent,
                    request_id=request_id,
                    success=False,
                )
                await self._uow.commit()
                raise AccountNotActiveError()

            if not user.is_active:
                await self._uow.audit.log(
                    action=AuditAction.USER_LOGIN_FAILED.value,
                    actor_uid=user.uid,
                    details={"reason": "account_not_active"},
                    ip_address=ip_address,
                    user_agent=user_agent,
                    request_id=request_id,
                    success=False,
                )
                await self._uow.commit()
                raise AccountNotActiveError()

            if user.two_factor_enabled:
                if not totp_code:
                    raise TwoFactorRequiredError()
                secret = self._totp.decrypt_secret(user.totp_secret)
                if not self._totp.verify_code(secret, totp_code):
                    await self._uow.audit.log(
                        action=AuditAction.TWO_FACTOR_FAILED.value,
                        actor_uid=user.uid,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        request_id=request_id,
                        success=False,
                    )
                    await self._uow.commit()
                    raise InvalidTwoFactorCodeError()

            if self._hasher.needs_rehash(user.password_hash):
                user.password_hash = self._hasher.hash(password)
                await self._uow.users.update(user)

            access_token = self._tokens.create_access_token(user)

            plain_refresh_token = self._refresh.generate_token()
            refresh_session = self._refresh.create_session(
                token=plain_refresh_token,
                user_uid=user.uid,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            active_count = (
                await self._uow.refresh_sessions.count_active_sessions(
                    user.uid,
                )
            )
            if active_count >= settings.MAX_SESSIONS_PER_USER:
                sessions = (
                    await self._uow.refresh_sessions.get_active_sessions(
                        user.uid
                    )
                )
                if sessions:
                    oldest = sessions[-1]
                    await self._uow.refresh_sessions.revoke(
                        oldest.token_hash
                    )

            await self._uow.refresh_sessions.create(refresh_session)

            await self._uow.audit.log(
                action=AuditAction.USER_LOGIN_SUCCESS.value,
                actor_uid=user.uid,
                details={
                    "device": refresh_session.device_name,
                },
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )

            await self._uow.commit()

            return {
                "access_token": access_token,
                "refresh_token": plain_refresh_token,
                "token_type": "bearer",
                "expires_in": (
                    settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
                ),
            }


    async def login_2fa(
        self,
        auth_token: str,
        totp_code: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        payload = self._tokens.verify


    async def refresh_tokens(
        self,
        refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> dict:
        token_hash = self._refresh.hash_token(refresh_token)

        async with self._uow:
            session = (
                await self._uow.refresh_sessions.get_by_token_hash(
                    token_hash
                )
            )

            if session is None:
                raise InvalidTokenError(reason="Refresh token not found")

            if session.replaced_by is not None:
                logger.warning(
                    {
                        "event": "refresh_token_reuse_detected",
                        "user_uid": str(session.user_uid),
                        "ip_address": ip_address,
                    }
                )
                await self._uow.refresh_sessions.revoke_all_for_user(
                    session.user_uid
                )
                await self._uow.audit.log(
                    action=AuditAction.USER_LOGOUT_ALL.value,
                    actor_uid=session.user_uid,
                    details={"reason": "refresh_token_reuse_detected"},
                    ip_address=ip_address,
                    request_id=request_id,
                    success=False,
                )
                await self._uow.commit()
                raise TokenRevokedException()

            if session.is_revoked:
                raise TokenRevokedException()

            if session.is_expired:
                raise TokenExpiredError()

            user = await self._uow.users.get_by_id(session.user_uid)
            if user is None:
                raise InvalidCredentialsError()
            if not user.is_active:
                raise AccountNotActiveError()

            access_token = self._tokens.create_access_token(user)
            new_plain_token = self._refresh.generate_token()
            new_session = self._refresh.create_session(
                token=new_plain_token,
                user_uid=user.uid,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            await self._uow.refresh_sessions.mark_replaced(
                old_token_hash=token_hash,
                new_token_hash=new_session.token_hash,
            )

    
            await self._uow.refresh_sessions.update_last_used(
                new_session.token_hash,
            )

            await self._uow.refresh_sessions.create(new_session)

            await self._uow.audit.log(
                action=AuditAction.TOKEN_REFRESHED.value,
                actor_uid=user.uid,
                ip_address=ip_address,
                request_id=request_id,
            )

            await self._uow.commit()

            return {
                "access_token": access_token,
                "refresh_token": new_plain_token,
                "token_type": "bearer",
                "expires_in": (
                    settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
                ),
            }

    async def logout(
        self,
        refresh_token: str,
        token_payload: TokenPayload,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        token_hash = self._refresh.hash_token(refresh_token)

        async with self._uow:
            await self._uow.refresh_sessions.revoke(token_hash)

            await self._uow.audit.log(
                action=AuditAction.USER_LOGOUT.value,
                actor_uid=token_payload.sub,
                ip_address=ip_address,
                request_id=request_id,
            )
            await self._uow.commit()

    async def logout_all_devices(
        self,
        token_payload: TokenPayload,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        async with self._uow:
            revoked_count = (
                await self._uow.refresh_sessions.revoke_all_for_user(
                    token_payload.sub
                )
            )

            await self._uow.audit.log(
                action=AuditAction.USER_LOGOUT_ALL.value,
                actor_uid=token_payload.sub,
                details={"revoked_sessions": revoked_count},
                ip_address=ip_address,
                request_id=request_id,
            )
            await self._uow.commit()

    async def get_active_sessions(self, user_uid) -> list[dict]:
        async with self._uow:
            sessions = (
                await self._uow.refresh_sessions.get_active_sessions(
                    user_uid
                )
            )
            return [
                {
                    "device": s.device_name or "Unknown device",
                    "ip_address": s.ip_address,
                    "created_at": s.created_at.isoformat(),
                    "last_used_at": (
                        s.last_used_at.isoformat()
                        if s.last_used_at else None
                    ),
                }
                for s in sessions
            ]

    async def confirm_email(
        self, token: str,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        data = self._url_tokens.decode_token(
            token=token,
            purpose=TokenPurpose.EMAIL_CONFIRMATION.value,
            max_age=settings.EMAIL_CONFIRM_TOKEN_EXPIRE_SECONDS,
        )
        email = data.get("email")
        if not email:
            raise InvalidCredentialsError()

        async with self._uow:
            user = await self._uow.users.get_by_email(email)
            if user is None:
                raise UserNotFoundError()
            if user.is_email_verified:
                return  
            
            user.is_email_verified = True
            user.is_active = True

            await self._uow.users.update(user)
            await self._uow.audit.log(
                action=AuditAction.EMAIL_CONFIRMED.value,
                actor_uid=user.uid,
                target_uid=user.uid,
                ip_address=ip_address,
                request_id=request_id,
            )
            await self._uow.commit()

    async def request_password_reset(
        self, email: str,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        async with self._uow:
            user = await self._uow.users.get_by_email(email)
            await self._uow.audit.log(
                action=AuditAction.PASSWORD_RESET_REQUESTED.value,
                actor_uid=user.uid if user else None,
                ip_address=ip_address,
                request_id=request_id,
            )
            await self._uow.commit()

        if user is not None:
            token = self._url_tokens.create_token(
                data={"email": email, "uid": str(user.uid)},
                purpose=TokenPurpose.PASSWORD_RESET.value,
            )
            await self._email.send_password_reset_email(
                email=email, username=user.username, token=token,
            )

    async def reset_password(
        self, token: str, new_password: str,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        data = self._url_tokens.decode_token(
            token=token,
            purpose=TokenPurpose.PASSWORD_RESET.value,
            max_age=settings.PASSWORD_RESET_TOKEN_EXPIRE_SECONDS,
        )
        email = data.get("email")
        if not email:
            raise InvalidCredentialsError()

        async with self._uow:
            user = await self._uow.users.get_by_email(email)
            if user is None:
                raise UserNotFoundError()

            user.password_hash = self._hasher.hash(new_password)
            await self._uow.users.update(user)

            revoked = (
                await self._uow.refresh_sessions.revoke_all_for_user(
                    user.uid
                )
            )

            await self._uow.audit.log(
                action=AuditAction.PASSWORD_RESET_COMPLETED.value,
                actor_uid=user.uid,
                target_uid=user.uid,
                details={"revoked_sessions": revoked},
                ip_address=ip_address,
                request_id=request_id,
            )
            await self._uow.commit()

    async def _send_confirmation_email(
        self, user: UserEntity,
    ) -> None:
        token = self._url_tokens.create_token(
            data={"email": user.email},
            purpose=TokenPurpose.EMAIL_CONFIRMATION.value,
        )
        await self._email.send_confirmation_email(
            email=user.email, username=user.username, token=token,
        )

    async def resend_confirmation_email(
        self,
        email: str,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        async with self._uow:
            user = await self._uow.users.get_by_email(email)

            await self._uow.audit.log(
                action=AuditAction.EMAIL_CONFIRMATION_SENT.value,
                actor_uid=user.uid if user else None,
                ip_address=ip_address,
                request_id=request_id,
            )
            await self._uow.commit()

        if user is not None and not user.is_email_verified:
            await self._send_confirmation_email(user)
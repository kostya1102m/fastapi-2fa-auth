import logging
from uuid import UUID

from src.core.exceptions import (
    InvalidCredentialsError,
    InvalidTwoFactorCodeError,
    SamePasswordError,
    TwoFactorAlreadyEnabledError,
    TwoFactorNotEnabledError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from src.core.protocols import (
    PasswordHasherProtocol,
    TOTPServiceProtocol,
    UnitOfWorkProtocol,
)
from src.domain.entities import UserEntity

logger = logging.getLogger(__name__)


class ProfileService:
    def __init__(
        self,
        uow: UnitOfWorkProtocol,
        hasher: PasswordHasherProtocol,
        totp_service: TOTPServiceProtocol,
    ):
        self._uow = uow
        self._hasher = hasher
        self._totp = totp_service

    async def get_profile(self, user_uid: UUID) -> UserEntity:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()
            return user

    async def change_password(
        self,
        user_uid: UUID,
        current_password: str,
        new_password: str,
    ) -> None:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if not self._hasher.verify(current_password, user.password_hash):
                raise InvalidCredentialsError()

            if self._hasher.verify(new_password, user.password_hash):
                raise SamePasswordError()

            user.password_hash = self._hasher.hash(new_password)
            await self._uow.users.update(user)

            await self._uow.refresh_sessions.revoke_all_for_user(user_uid)

            await self._uow.commit()

            logger.info(
                {
                    "event": "password_changed",
                    "user_uid": str(user_uid),
                }
            )

    async def change_username(
        self, user_uid: UUID, new_username: str,
    ) -> UserEntity:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if user.username == new_username:
                return user

            if await self._uow.users.exists_by_username(new_username):
                raise UserAlreadyExistsError(field="username")

            user.username = new_username
            updated = await self._uow.users.update(user)
            await self._uow.commit()

            logger.info(
                {
                    "event": "username_changed",
                    "user_uid": str(user_uid),
                }
            )
            return updated

    async def change_phone(
        self, user_uid: UUID, new_phone: str | None,
    ) -> UserEntity:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if user.phone_number == new_phone:
                return user

            if new_phone and await self._uow.users.exists_by_phone(new_phone):
                raise UserAlreadyExistsError(field="phone number")

            user.phone_number = new_phone
            updated = await self._uow.users.update(user)
            await self._uow.commit()

            logger.info(
                {
                    "event": "phone_changed",
                    "user_uid": str(user_uid),
                }
            )
            return updated

    async def setup_2fa(self, user_uid: UUID) -> dict:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if user.two_factor_enabled:
                raise TwoFactorAlreadyEnabledError()

            secret = self._totp.generate_secret()
            uri = self._totp.generate_uri(secret, user.email)
            qr_base64 = self._totp.generate_qr_base64(uri)

            user.totp_secret = self._totp.encrypt_secret(secret)
            await self._uow.users.update(user)
            await self._uow.commit()

            logger.info(
                {
                    "event": "2fa_setup_initiated",
                    "user_uid": str(user_uid),
                }
            )

            return {
                "qr_code_base64": qr_base64,
                "secret": secret,
                "uri": uri,
            }


    async def confirm_2fa(self, user_uid: UUID, code: str) -> None:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if user.two_factor_enabled:
                raise TwoFactorAlreadyEnabledError()

            if not user.totp_secret:
                raise TwoFactorNotEnabledError()

            secret = self._totp.decrypt_secret(user.totp_secret)
            if not self._totp.verify_code(secret, code):
                raise InvalidTwoFactorCodeError()

            user.two_factor_enabled = True
            await self._uow.users.update(user)
            await self._uow.commit()

            logger.info(
                {
                    "event": "2fa_enabled",
                    "user_uid": str(user_uid),
                }
            )

    async def disable_2fa(
        self, user_uid: UUID, code: str, password: str,
    ) -> None:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if not user.two_factor_enabled:
                raise TwoFactorNotEnabledError()

            if not self._hasher.verify(password, user.password_hash):
                raise InvalidCredentialsError()

            secret = self._totp.decrypt_secret(user.totp_secret)
            if not self._totp.verify_code(secret, code):
                raise InvalidTwoFactorCodeError()

            user.two_factor_enabled = False
            user.totp_secret = None
            await self._uow.users.update(user)
            await self._uow.commit()

            logger.info(
                {
                    "event": "2fa_disabled",
                    "user_uid": str(user_uid),
                }
            )
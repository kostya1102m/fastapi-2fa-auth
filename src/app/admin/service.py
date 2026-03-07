import logging
from uuid import UUID

from src.core.constants import AuditAction, UserRole
from src.core.exceptions import (
    AuthorizationError,
    UserNotFoundError,
)
from src.core.protocols import UnitOfWorkProtocol
from src.domain.entities import UserEntity

logger = logging.getLogger(__name__)


class AdminService:

    def __init__(self, uow: UnitOfWorkProtocol):
        self._uow = uow

    async def list_users(
        self, offset: int = 0, limit: int = 50,
    ) -> tuple[list[UserEntity], int]:
        async with self._uow:
            users = await self._uow.users.get_all(
                offset=offset, limit=limit,
            )
            total = await self._uow.users.count()
            return users, total

    async def get_user(self, user_uid: UUID) -> UserEntity:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()
            return user

    async def change_role(
        self,
        user_uid: UUID,
        new_role: UserRole,
        actor_uid: UUID | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> UserEntity:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if new_role == UserRole.OWNER:
                raise AuthorizationError(
                    message="OWNER role cannot be assigned through API",
                )
            if user.role == UserRole.OWNER:
                raise AuthorizationError(
                    message="Cannot change role of the OWNER",
                )
            if actor_uid and user_uid == actor_uid:
                raise AuthorizationError(
                    message="Cannot change your own role",
                )

            old_role = user.role
            user.role = new_role
            updated = await self._uow.users.update(user)

            await self._uow.audit.log(
                action=AuditAction.ROLE_CHANGED.value,
                actor_uid=actor_uid,
                target_uid=user_uid,
                details={
                    "old_role": old_role.value,
                    "new_role": new_role.value,
                },
                ip_address=ip_address,
                request_id=request_id,
            )

            await self._uow.commit()

            logger.info(
                {
                    "event": "role_changed",
                    "user_uid": str(user_uid),
                    "old_role": old_role.value,
                    "new_role": new_role.value,
                }
            )
            return updated

    async def delete_user(
        self,
        user_uid: UUID,
        actor_uid: UUID | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if user.role == UserRole.OWNER:
                raise AuthorizationError(
                    message="Cannot delete the OWNER account",
                )
            if actor_uid and user_uid == actor_uid:
                raise AuthorizationError(
                    message="Cannot delete your own account",
                )

            await self._uow.users.delete(user_uid)

            await self._uow.audit.log(
                action=AuditAction.USER_DELETED.value,
                actor_uid=actor_uid,
                target_uid=user_uid,
                ip_address=ip_address,
                request_id=request_id,
            )

            await self._uow.commit()

    async def deactivate_user(
        self,
        user_uid: UUID,
        actor_uid: UUID | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> UserEntity:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            if user.role == UserRole.OWNER:
                raise AuthorizationError(
                    message="Cannot deactivate the OWNER account",
                )

            user.is_active = False
            updated = await self._uow.users.update(user)

            await self._uow.audit.log(
                action=AuditAction.USER_DEACTIVATED.value,
                actor_uid=actor_uid,
                target_uid=user_uid,
                ip_address=ip_address,
                request_id=request_id,
            )

            await self._uow.commit()
            return updated

    async def activate_user(
        self,
        user_uid: UUID,
        actor_uid: UUID | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> UserEntity:
        async with self._uow:
            user = await self._uow.users.get_by_id(user_uid)
            if user is None:
                raise UserNotFoundError()

            user.is_active = True
            updated = await self._uow.users.update(user)

            await self._uow.audit.log(
                action=AuditAction.USER_ACTIVATED.value,
                actor_uid=actor_uid,
                target_uid=user_uid,
                ip_address=ip_address,
                request_id=request_id,
            )

            await self._uow.commit()
            return updated

    async def get_audit_log(
        self,
        user_uid: UUID | None = None,
        action: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[dict]:
        async with self._uow:
            if user_uid:
                return await self._uow.audit.get_user_history(
                    user_uid=user_uid,
                    offset=offset,
                    limit=limit,
                )
            elif action:
                return await self._uow.audit.get_by_action(
                    action=action,
                    offset=offset,
                    limit=limit,
                )
            else:
                return await self._uow.audit.get_all(
                    offset=offset,
                    limit=limit,
                )
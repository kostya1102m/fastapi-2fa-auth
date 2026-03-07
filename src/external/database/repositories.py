from uuid import UUID

from sqlalchemy import delete, func, select, exists
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.constants import UserRole
from src.core.protocols import UserRepositoryProtocol
from src.domain.entities import UserEntity
from src.external.database.models import UserModel


class UserRepository(UserRepositoryProtocol):
    def __init__(self, session: AsyncSession):
        self._session = session

    @staticmethod
    def _to_entity(model: UserModel) -> UserEntity:
        return UserEntity(
            uid=model.uid,
            username=model.username,
            email=model.email,
            password_hash=model.password_hash,
            phone_number=model.phone_number,
            role=model.role,
            is_active=model.is_active,
            two_factor_enabled=model.two_factor_enabled,
            totp_secret=model.totp_secret,
            created_at=model.created_at,
            updated_at=model.updated_at,
            is_email_verified=model.is_email_verified
        )

    @staticmethod
    def _to_model(entity: UserEntity) -> UserModel:
        return UserModel(
            uid=entity.uid,
            username=entity.username,
            email=entity.email,
            password_hash=entity.password_hash,
            phone_number=entity.phone_number,
            role=entity.role,
            is_active=entity.is_active,
            two_factor_enabled=entity.two_factor_enabled,
            totp_secret=entity.totp_secret,
            is_email_verified=entity.is_email_verified
        )

    async def get_by_id(self, uid: UUID) -> UserEntity | None:
        stmt = select(UserModel).where(UserModel.uid == uid)
        result = await self._session.execute(stmt)
        model = result.scalars().first()
        return self._to_entity(model) if model else None

    async def get_by_email(self, email: str) -> UserEntity | None:
        stmt = select(UserModel).where(
            UserModel.email == email.lower().strip()
        )
        result = await self._session.execute(stmt)
        model = result.scalars().first()
        return self._to_entity(model) if model else None

    async def get_by_username(self, username: str) -> UserEntity | None:
        stmt = select(UserModel).where(
            UserModel.username == username.strip()
        )
        result = await self._session.execute(stmt)
        model = result.scalars().first()
        return self._to_entity(model) if model else None

    async def get_by_phone(self, phone: str) -> UserEntity | None:
        stmt = select(UserModel).where(UserModel.phone_number == phone)
        result = await self._session.execute(stmt)
        model = result.scalars().first()
        return self._to_entity(model) if model else None

    async def get_all(
        self, offset: int = 0, limit: int = 50
    ) -> list[UserEntity]:
        stmt = (
            select(UserModel)
            .order_by(UserModel.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]

    async def count(self) -> int:
        stmt = select(func.count(UserModel.uid))
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def create(self, user: UserEntity) -> UserEntity:
        model = self._to_model(user)
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return self._to_entity(model)

    async def update(self, user: UserEntity) -> UserEntity:
        stmt = select(UserModel).where(UserModel.uid == user.uid)
        result = await self._session.execute(stmt)
        model = result.scalars().first()

        if model is None:
            raise ValueError(f"User {user.uid} not found for update")

        model.username = user.username
        model.email = user.email
        model.password_hash = user.password_hash
        model.phone_number = user.phone_number
        model.role = user.role
        model.is_active = user.is_active
        model.two_factor_enabled = user.two_factor_enabled
        model.totp_secret = user.totp_secret
        model.is_email_verified = user.is_email_verified

        await self._session.flush()
        await self._session.refresh(model)
        return self._to_entity(model)

    async def delete(self, uid: UUID) -> None:
        stmt = delete(UserModel).where(UserModel.uid == uid)
        await self._session.execute(stmt)
        await self._session.flush()

    async def exists_by_email(self, email: str) -> bool:
        stmt = select(
            exists().where(UserModel.email == email.lower().strip())
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def exists_by_username(self, username: str) -> bool:
        stmt = select(
            exists().where(UserModel.username == username.strip())
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def exists_by_phone(self, phone: str) -> bool:
        stmt = select(
            exists().where(UserModel.phone_number == phone)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.protocols import RefreshSessionRepositoryProtocol
from src.domain.entities import RefreshSession
from src.external.database.models import RefreshSessionModel


class RefreshSessionRepository(RefreshSessionRepositoryProtocol):
    def __init__(self, session: AsyncSession):
        self._session = session

    @staticmethod
    def _to_entity(model: RefreshSessionModel) -> RefreshSession:
        return RefreshSession(
            id=model.id,
            token_hash=model.token_hash,
            user_uid=model.user_uid,
            ip_address=model.ip_address,
            user_agent=model.user_agent,
            device_name=model.device_name,
            is_revoked=model.is_revoked,
            created_at=model.created_at,
            expires_at=model.expires_at,
            last_used_at=model.last_used_at,
            replaced_by=model.replaced_by,
        )
    
    async def create(self, session: RefreshSession) -> RefreshSession:
        model = RefreshSessionModel(
            token_hash=session.token_hash,
            user_uid=session.user_uid,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            device_name=session.device_name,
            is_revoked=False,
            expires_at=session.expires_at,
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)
        return self._to_entity(model)

    async def revoke(self, token_hash: str) -> None:
        stmt = (
            update(RefreshSessionModel)
            .where(RefreshSessionModel.token_hash == token_hash)
            .values(is_revoked=True)
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def revoke_all_for_user(self, user_uid: UUID) -> int:
        stmt = (
            update(RefreshSessionModel)
            .where(
                RefreshSessionModel.user_uid == user_uid,
                RefreshSessionModel.is_revoked == False,
            )
            .values(is_revoked=True)
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount

    async def mark_replaced(
        self, old_token_hash: str, new_token_hash: str,
    ) -> None:
        stmt = (
            update(RefreshSessionModel)
            .where(RefreshSessionModel.token_hash == old_token_hash)
            .values(
                is_revoked=True,
                replaced_by=new_token_hash,
            )
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def update_last_used(self, token_hash: str) -> None:
        stmt = (
            update(RefreshSessionModel)
            .where(RefreshSessionModel.token_hash == token_hash)
            .values(last_used_at=func.now())
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def get_by_token_hash(
        self, token_hash: str,
    ) -> RefreshSession | None:
        stmt = select(RefreshSessionModel).where(
            RefreshSessionModel.token_hash == token_hash,
        )
        result = await self._session.execute(stmt)
        model = result.scalars().first()
        return self._to_entity(model) if model else None

    async def get_active_sessions(
        self, user_uid: UUID,
    ) -> list[RefreshSession]:
        now = datetime.now(timezone.utc)
        stmt = (
            select(RefreshSessionModel)
            .where(
                RefreshSessionModel.user_uid == user_uid,
                RefreshSessionModel.is_revoked == False,
                RefreshSessionModel.expires_at > now,
            )
            .order_by(RefreshSessionModel.created_at.desc())
        )
        result = await self._session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]

    async def count_active_sessions(self, user_uid: UUID) -> int:
        now = datetime.now(timezone.utc)
        stmt = select(func.count(RefreshSessionModel.id)).where(
            RefreshSessionModel.user_uid == user_uid,
            RefreshSessionModel.is_revoked == False,
            RefreshSessionModel.expires_at > now,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def cleanup_expired(self) -> int:
        now = datetime.now(timezone.utc)
        stmt = delete(RefreshSessionModel).where(
            RefreshSessionModel.expires_at < now,
        )
        result = await self._session.execute(stmt)
        await self._session.flush()
        return result.rowcount
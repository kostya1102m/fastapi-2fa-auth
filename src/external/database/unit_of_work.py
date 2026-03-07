from src.core.protocols import (
    AuditLogProtocol,
    RefreshSessionRepositoryProtocol,
    UnitOfWorkProtocol,
    UserRepositoryProtocol,
)
from src.external.audit.db_audit import DatabaseAuditLog
from src.external.database.engine import async_session_factory
from src.external.database.refresh_session_repo import (
    RefreshSessionRepository,
)
from src.external.database.repositories import UserRepository


class SQLAlchemyUnitOfWork(UnitOfWorkProtocol):

    def __init__(self):
        self._session_factory = async_session_factory

    async def __aenter__(self) -> "SQLAlchemyUnitOfWork":
        self._session = self._session_factory()
        self.users: UserRepositoryProtocol = UserRepository(self._session)
        self.refresh_sessions: RefreshSessionRepositoryProtocol = (
            RefreshSessionRepository(self._session)
        )
        self.audit: AuditLogProtocol = DatabaseAuditLog(self._session)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            await self.rollback()
        await self._session.close()

    async def commit(self) -> None:
        try:
            await self._session.commit()
        except Exception:
            await self.rollback()
            raise

    async def rollback(self) -> None:
        await self._session.rollback()
import logging
from datetime import datetime
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.protocols import AuditLogProtocol
from src.external.database.models import AuditLogModel

logger = logging.getLogger(__name__)


class DatabaseAuditLog(AuditLogProtocol):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def log(
        self,
        action: str,
        actor_uid: UUID | None = None,
        target_uid: UUID | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        success: bool = True,
    ) -> None:
        safe_details = self._sanitize_details(details) if details else None

        entry = AuditLogModel(
            actor_uid=actor_uid,
            target_uid=target_uid,
            action=action,
            details=safe_details,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            success=success,
        )

        self._session.add(entry)
        await self._session.flush()

    async def get_user_history(
        self,
        user_uid: UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> list[dict]:
        stmt = (
            select(AuditLogModel)
            .where(
                (AuditLogModel.actor_uid == user_uid)
                | (AuditLogModel.target_uid == user_uid)
            )
            .order_by(AuditLogModel.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        entries = result.scalars().all()
        return [self._to_dict(e) for e in entries]

    async def get_by_action(
        self,
        action: str,
        offset: int = 0,
        limit: int = 50,
    ) -> list[dict]:
        stmt = (
            select(AuditLogModel)
            .where(AuditLogModel.action == action)
            .order_by(AuditLogModel.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        entries = result.scalars().all()
        return [self._to_dict(e) for e in entries]

    @staticmethod
    def _sanitize_details(details: dict) -> dict:
        sensitive_keys = {
            "password", "password_hash", "current_password",
            "new_password", "token", "access_token", "refresh_token",
            "totp_secret", "secret", "code",
        }
        return {
            k: "***REDACTED***" if k.lower() in sensitive_keys else v
            for k, v in details.items()
        }

    @staticmethod
    def _to_dict(entry: AuditLogModel) -> dict:
        return {
            "id": entry.id,
            "actor_uid": str(entry.actor_uid) if entry.actor_uid else None,
            "target_uid": (
                str(entry.target_uid) if entry.target_uid else None
            ),
            "action": entry.action,
            "details": entry.details,
            "ip_address": entry.ip_address,
            "user_agent": entry.user_agent,
            "request_id": entry.request_id,
            "success": entry.success,
            "created_at": entry.created_at.isoformat(),
        }


    async def get_all(
        self, offset: int = 0, limit: int = 50,
    ) -> list[dict]:
        stmt = (
            select(AuditLogModel)
            .order_by(AuditLogModel.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        entries = result.scalars().all()
        return [self._to_dict(e) for e in entries]
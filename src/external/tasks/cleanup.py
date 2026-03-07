import asyncio
import logging

from src.external.database.engine import async_session_factory
from src.external.token_blacklist.db_blacklist import (
    DatabaseTokenBlacklist,
)

logger = logging.getLogger(__name__)


class TokenCleanupTask:
    def __init__(self, interval_seconds: int = 3600):
        self._interval = interval_seconds
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())
        logger.info(
            {
                "event": "cleanup_task_started",
                "interval_seconds": self._interval,
            }
        )

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info({"event": "cleanup_task_stopped"})

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self._cleanup()
            except Exception as e:
                logger.error(
                    {
                        "event": "cleanup_task_error",
                        "error": type(e).__name__,
                        "message": str(e),
                    }
                )

    async def _cleanup(self) -> None:
        async with async_session_factory() as session:
            blacklist = DatabaseTokenBlacklist(session)
            deleted = await blacklist.cleanup_expired()
            await session.commit()

            if deleted:
                logger.info(
                    {
                        "event": "expired_tokens_cleaned",
                        "deleted_count": deleted,
                    }
                )
import logging
from typing import Annotated

from fastapi import Depends, Request

from src.config import settings
from src.core.protocols import RateLimiterProtocol

logger = logging.getLogger(__name__)


def _get_rate_limiter() -> RateLimiterProtocol:
    from src.app.dependencies import get_rate_limiter
    return get_rate_limiter()


def _default_key_func(request: Request) -> str:
    client_ip = request.headers.get(
        "X-Forwarded-For", "",
    ).split(",")[0].strip()

    if not client_ip and request.client:
        client_ip = request.client.host

    return client_ip or "unknown"


class RateLimitDependency:
    def __init__(
        self,
        max_attempts: int,
        window_seconds: int,
        prefix: str = "",
        key_func: callable | None = None,
    ):
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._prefix = prefix
        self._key_func = key_func or _default_key_func

    async def __call__(
        self,
        request: Request,
        limiter: Annotated[
            RateLimiterProtocol,
            Depends(_get_rate_limiter),
        ],
    ) -> None:
        key = self._key_func(request)
        full_key = (
            f"{self._prefix}:{key}" if self._prefix else key
        )
        await limiter.check_rate_limit(
            key=full_key,
            max_attempts=self._max_attempts,
            window_seconds=self._window_seconds,
        )


login_rate_limit = RateLimitDependency(
    max_attempts=settings.RATE_LIMIT_LOGIN_ATTEMPTS,
    window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
    prefix="login",
)

register_rate_limit = RateLimitDependency(
    max_attempts=settings.RATE_LIMIT_REGISTER_ATTEMPTS,
    window_seconds=settings.RATE_LIMIT_REGISTER_WINDOW_SECONDS,
    prefix="register",
)

password_reset_rate_limit = RateLimitDependency(
    max_attempts=3,
    window_seconds=600,
    prefix="password_reset",
)
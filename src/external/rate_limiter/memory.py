import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field

from src.core.exceptions import RateLimitExceededError
from src.core.protocols import RateLimiterProtocol


@dataclass
class _BucketEntry:
    timestamps: list[float] = field(default_factory=list)


class InMemoryRateLimiter(RateLimiterProtocol):
    MAX_KEYS = 100_000

    def __init__(self, cleanup_interval: int = 300):
        self._buckets: dict[str, _BucketEntry] = defaultdict(_BucketEntry)
        self._lock = asyncio.Lock()
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def check_rate_limit(
        self, key: str, max_attempts: int, window_seconds: int,
    ) -> None:
        now = time.monotonic()

        async with self._lock:
            if (
                key not in self._buckets
                and len(self._buckets) >= self.MAX_KEYS
            ):
                await self._cleanup_stale_entries_locked(now)

                if len(self._buckets) >= self.MAX_KEYS:
                    raise RateLimitExceededError(retry_after=60)

            bucket = self._buckets[key]
            cutoff = now - window_seconds
            bucket.timestamps = [
                ts for ts in bucket.timestamps if ts > cutoff
            ]

            if len(bucket.timestamps) >= max_attempts:
                oldest = min(bucket.timestamps)
                retry_after = (
                    int(oldest + window_seconds - now) + 1
                )
                raise RateLimitExceededError(
                    retry_after=retry_after,
                )

            bucket.timestamps.append(now)

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._buckets.pop(key, None)

    async def get_remaining(
        self, key: str, max_attempts: int, window_seconds: int,
    ) -> tuple[int, int]:
        now = time.monotonic()

        async with self._lock:
            bucket = self._buckets.get(key)
            if not bucket:
                return max_attempts, 0

            cutoff = now - window_seconds
            active = [ts for ts in bucket.timestamps if ts > cutoff]

            remaining = max(0, max_attempts - len(active))
            if active:
                oldest = min(active)
                reset_in = int(oldest + window_seconds - now) + 1
            else:
                reset_in = 0

            return remaining, reset_in

    async def _periodic_cleanup(self) -> None:
        while True:
            await asyncio.sleep(self._cleanup_interval)
            await self._cleanup_stale_entries()

    async def _cleanup_stale_entries(self) -> None:
        now = time.monotonic()
        max_window = 3600

        async with self._lock:
            stale_keys = []
            for key, bucket in self._buckets.items():
                bucket.timestamps = [
                    ts for ts in bucket.timestamps
                    if ts > now - max_window
                ]
                if not bucket.timestamps:
                    stale_keys.append(key)

            for key in stale_keys:
                del self._buckets[key]

    async def _cleanup_stale_entries_locked(
        self, now: float,
    ) -> None:
        max_window = 3600
        stale_keys = []
        for key, bucket in self._buckets.items():
            bucket.timestamps = [
                ts for ts in bucket.timestamps
                if ts > now - max_window
            ]
            if not bucket.timestamps:
                stale_keys.append(key)
        for key in stale_keys:
            del self._buckets[key]
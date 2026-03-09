from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.asyncio import Redis


class RedisRateLimitStore:
    """Sliding-window rate limiter backed by Redis sorted sets."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def is_allowed(
        self, *, key: str, limit: int, window_seconds: int
    ) -> tuple[bool, int, int]:
        now = time.time()
        window_start = now - window_seconds

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, window_seconds)
        results = await pipe.execute()

        current_count: int = results[2]
        allowed = current_count <= limit
        remaining = max(0, limit - current_count)

        if allowed:
            retry_after = 0
        else:
            oldest_entries = await self._redis.zrange(key, 0, 0, withscores=True)
            if oldest_entries:
                oldest_score = oldest_entries[0][1]
                retry_after = max(1, int(oldest_score + window_seconds - now) + 1)
            else:
                retry_after = window_seconds

        return allowed, remaining, retry_after

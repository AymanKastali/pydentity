from __future__ import annotations

from typing import Protocol


class RateLimitStorePort(Protocol):
    async def is_allowed(
        self, *, key: str, limit: int, window_seconds: int
    ) -> tuple[bool, int, int]:
        """Check if a request is allowed under the rate limit.

        Returns:
            A tuple of (allowed, remaining, retry_after_seconds).
        """
        ...

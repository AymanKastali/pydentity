from __future__ import annotations

from datetime import UTC, datetime

from pydentity.domain.ports.clock import ClockPort


class UtcClock(ClockPort):
    def now(self) -> datetime:
        return datetime.now(UTC)

from datetime import UTC, datetime

from pydentity.application.services.clock import Clock


class UTCClock(Clock):
    def now(self) -> datetime:
        return datetime.now(UTC)

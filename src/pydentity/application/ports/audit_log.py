from __future__ import annotations

from abc import ABC, abstractmethod


class AuditLogPort(ABC):
    @abstractmethod
    async def record(
        self,
        *,
        action: str,
        user_id: str,
        session_id: str | None = None,
        device_id: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None: ...

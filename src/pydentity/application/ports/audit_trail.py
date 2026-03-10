from __future__ import annotations

from abc import ABC, abstractmethod


class AuditTrailPort(ABC):
    @abstractmethod
    async def record(
        self,
        *,
        action: str,
        category: str,
        actor_user_id: str,
        session_id: str | None = None,
        device_id: str | None = None,
        ip_address: str | None = None,
        trace_id: str | None = None,
        target_entity_type: str | None = None,
        target_entity_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None: ...

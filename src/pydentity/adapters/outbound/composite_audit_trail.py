from __future__ import annotations

import logging

from pydentity.application.ports.audit_trail import AuditTrailPort

_log = logging.getLogger("pydentity.audit.composite")


class CompositeAuditTrail(AuditTrailPort):
    def __init__(self, delegates: list[AuditTrailPort]) -> None:
        self._delegates = delegates

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
    ) -> None:
        for delegate in self._delegates:
            try:
                await delegate.record(
                    action=action,
                    category=category,
                    actor_user_id=actor_user_id,
                    session_id=session_id,
                    device_id=device_id,
                    ip_address=ip_address,
                    trace_id=trace_id,
                    target_entity_type=target_entity_type,
                    target_entity_id=target_entity_id,
                    metadata=metadata,
                )
            except Exception:
                _log.exception(
                    "audit delegate %s failed for action=%s",
                    type(delegate).__name__,
                    action,
                )

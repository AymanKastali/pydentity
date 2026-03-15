from __future__ import annotations

import logging

from pydentity.application.ports.audit_trail import AuditTrailPort

_log = logging.getLogger("pydentity.audit")


class LogAuditTrail(AuditTrailPort):
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
        extra: dict[str, object] = {
            "category": category,
            "actor_user_id": actor_user_id,
        }
        if session_id is not None:
            extra["session_id"] = session_id
        if device_id is not None:
            extra["device_id"] = device_id
        if ip_address:
            extra["ip_address"] = ip_address
        if trace_id:
            extra["trace_id"] = trace_id
        if target_entity_type is not None:
            extra["target_entity_type"] = target_entity_type
            extra["target_entity_id"] = target_entity_id
        if metadata:
            extra["metadata"] = metadata
        _log.info("audit action=%s", action, extra={"context": extra})

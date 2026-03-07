from __future__ import annotations

import logging

from pydentity.application.ports.audit_log import AuditLogPort

_log = logging.getLogger("pydentity.audit")


class LogAuditLog(AuditLogPort):
    async def record(
        self,
        *,
        action: str,
        user_id: str,
        session_id: str | None = None,
        device_id: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None:
        extra: dict[str, object] = {"user_id": user_id}
        if session_id is not None:
            extra["session_id"] = session_id
        if device_id is not None:
            extra["device_id"] = device_id
        if metadata:
            extra.update(metadata)
        _log.info("audit action=%s %s", action, extra)

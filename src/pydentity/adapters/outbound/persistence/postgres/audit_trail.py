from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydentity.adapters.outbound.persistence.postgres.models import AuditEventModel
from pydentity.application.ports.audit_trail import AuditTrailPort

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_log = logging.getLogger("pydentity.audit.postgres")


class PostgresAuditTrail(AuditTrailPort):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

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
        try:
            row = AuditEventModel(
                action=action,
                category=category,
                actor_user_id=actor_user_id,
                session_id=session_id,
                device_id=device_id,
                ip_address=ip_address,
                trace_id=trace_id,
                target_entity_type=target_entity_type,
                target_entity_id=target_entity_id,
                metadata_=metadata,
            )
            async with self._session_factory() as session:
                session.add(row)
                await session.commit()
        except Exception:
            _log.exception("failed to persist audit event action=%s", action)

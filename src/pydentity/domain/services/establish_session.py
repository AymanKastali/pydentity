from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from pydentity.domain.factories.session_factory import SessionFactory
    from pydentity.domain.models.session import Session
    from pydentity.domain.models.value_objects import DeviceId, UserId
    from pydentity.domain.ports.repositories import SessionRepositoryPort


class EstablishSession:
    def __init__(
        self,
        *,
        session_repo: SessionRepositoryPort,
        session_factory: SessionFactory,
    ) -> None:
        self._repo = session_repo
        self._factory = session_factory

    async def execute(
        self,
        *,
        user_id: UserId,
        device_id: DeviceId,
        raw_refresh_token: str,
        absolute_lifetime: timedelta,
        created_at: datetime,
    ) -> Session:
        existing = await self._repo.get_active_by_device(device_id)
        if existing:
            existing.revoke()
            await self._repo.save(existing)

        return self._factory.create(
            user_id=user_id,
            device_id=device_id,
            raw_refresh_token=raw_refresh_token,
            absolute_lifetime=absolute_lifetime,
            created_at=created_at,
        )

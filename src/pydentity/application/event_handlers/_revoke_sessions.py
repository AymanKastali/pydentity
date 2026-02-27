from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.value_objects import UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.domain.events.base import DomainEvent
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class _RevokeSessionsHandler:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher

    async def _revoke_all(self, user_id: str) -> None:
        async with self._uow_factory() as uow:
            sessions = await uow.sessions.find_active_by_user_id(UserId(value=user_id))

            for session in sessions:
                session.revoke()
                await uow.sessions.save(session)

            await uow.commit()

        all_events: list[DomainEvent] = []
        for session in sessions:
            all_events.extend(session.collect_events())

        await self._event_publisher.publish(all_events)
        for session in sessions:
            session.clear_events()

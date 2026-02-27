from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import SessionNotFoundError
from pydentity.domain.models.value_objects import SessionId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import LogoutUserInput
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class LogoutUser:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher

    async def execute(self, command: LogoutUserInput) -> None:
        async with self._uow_factory() as uow:
            session = await uow.sessions.find_by_id(SessionId(value=command.session_id))
            if session is None:
                raise SessionNotFoundError(session_id=command.session_id)

            session.revoke()

            await uow.sessions.save(session)
            await uow.commit()

            events = session.collect_events()

        await self._event_publisher.publish(events)
        session.clear_events()

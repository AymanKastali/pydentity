from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import InvalidTokenError
from pydentity.domain.models.value_objects import SessionId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.auth import LogoutUserInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class LogoutUser:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        event_publisher: DomainEventPublisherPort,
        logger: LoggerPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._logger = logger

    async def execute(self, command: LogoutUserInput) -> None:
        async with self._uow_factory() as uow:
            session = await uow.sessions.find_by_id(SessionId(value=command.session_id))
            if session is None:
                raise InvalidTokenError()

            if session.is_active:
                session.revoke()

            await uow.sessions.upsert(session)
            await uow.commit()

        self._logger.info("session revoked", session_id=command.session_id)

        events = session.collect_events()
        await self._event_publisher.publish(events)

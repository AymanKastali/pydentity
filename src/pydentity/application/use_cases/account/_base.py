from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import ResourceNotFoundError
from pydentity.domain.models.value_objects import UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.models.user import User
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class SingleUserCommand:
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

    async def _execute_on_user(
        self,
        user_id: str,
        action: Callable[[User], None],
        log_message: str,
    ) -> None:
        self._logger.debug("executing user command", user_id=user_id)

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=user_id))
            if user is None:
                self._logger.warning(
                    "user command failed — user not found", user_id=user_id
                )
                raise ResourceNotFoundError(resource="User", identifier=user_id)

            action(user)

            await uow.users.upsert(user)
            await uow.commit()

        self._logger.info(log_message, user_id=user_id)

        events = user.collect_events()
        await self._event_publisher.publish(events)

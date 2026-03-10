from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import UserNotFoundError
from pydentity.domain.models.value_objects import UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.password import ChangePasswordInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork
    from pydentity.domain.services.change_user_password import ChangeUserPassword


class ChangePassword:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        change_user_password: ChangeUserPassword,
        event_publisher: DomainEventPublisherPort,
        logger: LoggerPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._change_user_password = change_user_password
        self._event_publisher = event_publisher
        self._logger = logger

    async def execute(self, command: ChangePasswordInput) -> None:
        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                raise UserNotFoundError(user_id=command.user_id)

            await self._change_user_password.execute(
                user=user,
                current_password=command.current_password,
                new_password=command.new_password,
            )

            await uow.users.upsert(user)
            await uow.commit()

        self._logger.info("password changed", user_id=command.user_id)

        events = user.collect_events()
        await self._event_publisher.publish(events)

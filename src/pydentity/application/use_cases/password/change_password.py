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
        self._logger.debug("changing password", user_id=command.user_id)

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                self._logger.warning(
                    "password change failed — user not found", user_id=command.user_id
                )
                raise UserNotFoundError(user_id=command.user_id)

            await self._change_user_password.execute(
                user=user,
                current_password=command.current_password,
                new_password=command.new_password,
            )

            await uow.users.upsert(user)

            active_sessions = await uow.sessions.find_active_by_user_id(
                UserId(value=command.user_id)
            )
            for session in active_sessions:
                session.revoke()
                await uow.sessions.upsert(session)

            await uow.commit()

        self._logger.info("password changed", user_id=command.user_id)

        events = user.collect_events()
        for session in active_sessions:
            events.extend(session.collect_events())
        await self._event_publisher.publish(events)

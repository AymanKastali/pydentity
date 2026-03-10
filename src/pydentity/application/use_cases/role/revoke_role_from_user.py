from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import UserNotFoundError
from pydentity.domain.models.value_objects import RoleId, UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import RevokeRoleFromUserInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class RevokeRoleFromUser:
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

    async def execute(self, command: RevokeRoleFromUserInput) -> None:
        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                raise UserNotFoundError(user_id=command.user_id)

            user.revoke_role(RoleId(value=command.role_id))

            await uow.users.upsert(user)
            await uow.commit()

        self._logger.info(
            "role revoked", role_id=command.role_id, user_id=command.user_id
        )

        events = user.collect_events()
        await self._event_publisher.publish(events)

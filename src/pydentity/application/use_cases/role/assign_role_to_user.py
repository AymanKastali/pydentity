from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import RoleNotFoundError, UserNotFoundError
from pydentity.domain.models.value_objects import RoleId, UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import AssignRoleToUserInput
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class AssignRoleToUser:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher

    async def execute(self, command: AssignRoleToUserInput) -> None:
        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=command.user_id))
            if user is None:
                raise UserNotFoundError(user_id=command.user_id)

            role_id = RoleId(value=command.role_id)
            role = await uow.roles.find_by_id(role_id)
            if role is None:
                raise RoleNotFoundError(role_id=command.role_id)

            user.assign_role(role_id)

            await uow.users.save(user)
            await uow.commit()

            events = user.collect_events()

        await self._event_publisher.publish(events)
        user.clear_events()

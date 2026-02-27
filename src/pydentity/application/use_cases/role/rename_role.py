from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import RoleNotFoundError
from pydentity.domain.models.value_objects import RoleId, RoleName

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import RenameRoleInput
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class RenameRole:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher

    async def execute(self, command: RenameRoleInput) -> None:
        async with self._uow_factory() as uow:
            role = await uow.roles.find_by_id(RoleId(value=command.role_id))
            if role is None:
                raise RoleNotFoundError(role_id=command.role_id)

            role.rename(RoleName(value=command.new_name))

            await uow.roles.save(role)
            await uow.commit()

            events = role.collect_events()

        await self._event_publisher.publish(events)
        role.clear_events()

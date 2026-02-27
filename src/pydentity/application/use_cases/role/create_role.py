from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.value_objects import RoleDescription, RoleName

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import CreateRoleInput, CreateRoleOutput
    from pydentity.domain.factories import RoleFactory
    from pydentity.domain.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class CreateRole:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        role_factory: RoleFactory,
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._role_factory = role_factory
        self._event_publisher = event_publisher

    async def execute(self, command: CreateRoleInput) -> CreateRoleOutput:
        from pydentity.application.dtos.role import CreateRoleOutput

        role = self._role_factory.create(
            name=RoleName(value=command.name),
            description=RoleDescription(value=command.description),
        )

        async with self._uow_factory() as uow:
            await uow.roles.save(role)
            await uow.commit()

            events = role.collect_events()

        await self._event_publisher.publish(events)
        role.clear_events()

        return CreateRoleOutput(
            role_id=role.id.value,
            name=role.name.value,
            description=role.description.value,
        )

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import RoleAlreadyExistsError
from pydentity.domain.models.value_objects import RoleDescription, RoleName

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import CreateRoleInput, CreateRoleOutput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork
    from pydentity.domain.services.create_role import CreateRole as CreateRoleService


class CreateRole:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        create_role_service: CreateRoleService,
        event_publisher: DomainEventPublisherPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._create_role_service = create_role_service
        self._event_publisher = event_publisher

    async def execute(self, command: CreateRoleInput) -> CreateRoleOutput:
        from pydentity.application.dtos.role import CreateRoleOutput

        async with self._uow_factory() as uow:
            try:
                role = await self._create_role_service.execute(
                    name=RoleName(value=command.name),
                    description=RoleDescription(value=command.description),
                )
            except RoleAlreadyExistsError:
                raise

            await uow.roles.save(role)
            await uow.commit()

        events = role.collect_events()
        await self._event_publisher.publish(events)

        return CreateRoleOutput(
            role_id=role.id.value,
            name=role.name.value,
            description=role.description.value,
        )

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.dtos.role import CreateRoleOutput
from pydentity.domain.models.value_objects import RoleDescription, RoleName
from pydentity.domain.services.create_role import CreateRole as CreateRoleService

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import CreateRoleInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class CreateRole:
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

    async def execute(self, command: CreateRoleInput) -> CreateRoleOutput:
        self._logger.debug("creating role", role_name=command.name)

        async with self._uow_factory() as uow:
            create_role_service = CreateRoleService(
                role_repo=uow.roles,
            )
            role = await create_role_service.execute(
                name=RoleName.create(command.name),
                description=RoleDescription.create(command.description),
            )

            await uow.roles.upsert(role)
            await uow.commit()

        self._logger.info("role created", role_name=command.name)

        events = role.collect_events()
        await self._event_publisher.publish(events)

        return CreateRoleOutput(
            name=role.name.value,
            description=role.description.value,
        )

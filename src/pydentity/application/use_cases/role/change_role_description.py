from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import ResourceNotFoundError
from pydentity.domain.models.value_objects import RoleDescription, RoleName

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import ChangeRoleDescriptionInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class ChangeRoleDescription:
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

    async def execute(self, command: ChangeRoleDescriptionInput) -> None:
        self._logger.debug("changing role description", role_name=command.role_name)

        async with self._uow_factory() as uow:
            role = await uow.roles.find_by_name(RoleName.create(command.role_name))
            if role is None:
                self._logger.warning(
                    "role description change failed — role not found",
                    role_name=command.role_name,
                )
                raise ResourceNotFoundError(
                    resource="Role", identifier=command.role_name
                )

            role.change_description(RoleDescription.create(command.new_description))

            await uow.roles.upsert(role)
            await uow.commit()

        self._logger.info("role description changed", role_name=command.role_name)

        events = role.collect_events()
        await self._event_publisher.publish(events)

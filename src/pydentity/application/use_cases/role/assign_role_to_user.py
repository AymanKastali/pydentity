from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from pydentity.application.exceptions import ResourceNotFoundError
from pydentity.domain.models.value_objects import RoleName, UserId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import AssignRoleToUserInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class AssignRoleToUser:
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

    async def execute(self, command: AssignRoleToUserInput) -> None:
        self._logger.debug(
            "assigning role", role_name=command.role_name, user_id=command.user_id
        )

        async with self._uow_factory() as uow:
            user = await uow.users.find_by_id(UserId(value=UUID(command.user_id)))
            if user is None:
                self._logger.warning(
                    "role assignment failed — user not found", user_id=command.user_id
                )
                raise ResourceNotFoundError(resource="User", identifier=command.user_id)

            role_name = RoleName.create(command.role_name)
            role = await uow.roles.find_by_name(role_name)
            if role is None:
                self._logger.warning(
                    "role assignment failed — role not found",
                    role_name=command.role_name,
                )
                raise ResourceNotFoundError(
                    resource="Role", identifier=command.role_name
                )

            user.assign_role(role.name)

            await uow.users.upsert(user)
            await uow.commit()

        self._logger.info(
            "role assigned", role_name=command.role_name, user_id=command.user_id
        )

        events = user.collect_events()
        await self._event_publisher.publish(events)

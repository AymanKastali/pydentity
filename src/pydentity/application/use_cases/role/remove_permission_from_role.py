from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.exceptions import RoleNotFoundError
from pydentity.domain.models.value_objects import Permission, RoleId

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.application.dtos.role import RemovePermissionFromRoleInput
    from pydentity.application.ports.event_publisher import DomainEventPublisherPort
    from pydentity.application.ports.logger import LoggerPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork


class RemovePermissionFromRole:
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

    async def execute(self, command: RemovePermissionFromRoleInput) -> None:
        async with self._uow_factory() as uow:
            role = await uow.roles.find_by_id(RoleId(value=command.role_id))
            if role is None:
                raise RoleNotFoundError(role_id=command.role_id)

            role.remove_permission(
                Permission(value=f"{command.resource}:{command.action}")
            )

            await uow.roles.upsert(role)
            await uow.commit()

        self._logger.info(
            "permission removed from role",
            role_id=command.role_id,
            resource=command.resource,
            action=command.action,
        )

        events = role.collect_events()
        await self._event_publisher.publish(events)

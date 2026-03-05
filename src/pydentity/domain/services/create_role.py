from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import RoleAlreadyExistsError

if TYPE_CHECKING:
    from pydentity.domain.factories.role_factory import RoleFactory
    from pydentity.domain.models.role import Role
    from pydentity.domain.models.value_objects import RoleDescription, RoleName
    from pydentity.domain.ports.repositories import RoleRepositoryPort


class CreateRole:
    def __init__(
        self,
        *,
        role_repo: RoleRepositoryPort,
        role_factory: RoleFactory,
    ) -> None:
        self._repo = role_repo
        self._factory = role_factory

    async def execute(
        self,
        *,
        name: RoleName,
        description: RoleDescription,
    ) -> Role:
        existing = await self._repo.find_by_name(name)
        if existing:
            raise RoleAlreadyExistsError()

        return self._factory.create(
            name=name,
            description=description,
        )

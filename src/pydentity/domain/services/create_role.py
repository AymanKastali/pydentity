from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import RoleAlreadyExistsError
from pydentity.domain.models.role import Role

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import RoleDescription, RoleName
    from pydentity.domain.ports.repositories import RoleRepositoryPort


class CreateRole:
    def __init__(
        self,
        *,
        role_repo: RoleRepositoryPort,
    ) -> None:
        self._repo = role_repo

    async def execute(
        self,
        *,
        name: RoleName,
        description: RoleDescription,
    ) -> Role:
        if await self._repo.check_name_exists(name):
            raise RoleAlreadyExistsError()

        return Role.create(
            name=name,
            description=description,
        )

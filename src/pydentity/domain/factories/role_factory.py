from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.role import Role

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import RoleDescription, RoleName


class RoleFactory:
    def create(
        self,
        *,
        name: RoleName,
        description: RoleDescription,
    ) -> Role:
        return Role.create(
            name=name,
            description=description,
        )

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.role import Role

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import RoleDescription, RoleName
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort


class RoleFactory:
    def __init__(self, *, identity_generator: IdentityGeneratorPort) -> None:
        self._identity_generator = identity_generator

    def create(
        self,
        *,
        name: RoleName,
        description: RoleDescription,
    ) -> Role:
        role_id = self._identity_generator.new_role_id()
        return Role.create(
            role_id=role_id,
            name=name,
            description=description,
        )

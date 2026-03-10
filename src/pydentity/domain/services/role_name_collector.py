from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pydentity.domain.models.role import Role
    from pydentity.domain.models.value_objects import RoleName


def collect_role_names(roles: Iterable[Role]) -> frozenset[RoleName]:
    return frozenset(role.name for role in roles)

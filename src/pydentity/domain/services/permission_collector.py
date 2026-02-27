from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pydentity.domain.models.role import Role
    from pydentity.domain.models.value_objects import Permission


def collect_permissions(roles: Iterable[Role]) -> frozenset[Permission]:
    return frozenset(perm for role in roles for perm in role.permissions)

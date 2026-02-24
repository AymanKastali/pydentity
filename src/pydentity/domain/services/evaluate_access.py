from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import Permission


def evaluate_access(
    granted_permissions: frozenset[Permission],
    required: Permission,
) -> bool:
    return required in granted_permissions

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.events.role_events import (
    PermissionAddedToRole,
    PermissionRemovedFromRole,
    RoleCreated,
    RoleDescriptionChanged,
)
from pydentity.domain.exceptions import (
    PermissionAlreadyGrantedError,
    PermissionNotGrantedError,
)
from pydentity.domain.guards import verify_params
from pydentity.domain.models.base import AggregateRoot
from pydentity.domain.models.value_objects import Permission, RoleDescription, RoleName

if TYPE_CHECKING:
    from collections.abc import Iterable


class Role(AggregateRoot[RoleName]):
    def __init__(
        self,
        *,
        name: RoleName,
        description: RoleDescription,
        permissions: set[Permission],
    ) -> None:
        super().__init__()
        verify_params(
            name=(name, RoleName),
            description=(description, RoleDescription),
            permissions=(permissions, set),
        )
        self._id = name
        self._description = description
        self._permissions = set(permissions)

    @classmethod
    def create(
        cls,
        name: RoleName,
        description: RoleDescription,
    ) -> Role:
        role = cls(
            name=name,
            description=description,
            permissions=set(),
        )

        role._record_event(
            RoleCreated(
                role_name=role._id.value,
                description=description.value,
            )
        )
        return role

    @classmethod
    def _reconstitute(
        cls,
        name: RoleName,
        description: RoleDescription,
        permissions: set[Permission],
    ) -> Role:
        return cls(
            name=name,
            description=description,
            permissions=permissions,
        )

    # --- Read-only properties ---

    @property
    def name(self) -> RoleName:
        return self._id

    @property
    def description(self) -> RoleDescription:
        return self._description

    @property
    def permissions(self) -> frozenset[Permission]:
        return frozenset(self._permissions)

    # --- Helpers ---

    def _ensure_permission_not_granted(self, permission: Permission) -> None:
        if permission in self._permissions:
            raise PermissionAlreadyGrantedError(
                permission=permission, role_name=self._id.value
            )

    def _ensure_permission_granted(self, permission: Permission) -> None:
        if permission not in self._permissions:
            raise PermissionNotGrantedError(
                permission=permission, role_name=self._id.value
            )

    # --- Commands ---

    def add_permission(self, permission: Permission) -> None:
        self._ensure_permission_not_granted(permission)

        self._permissions.add(permission)

        self._record_event(
            PermissionAddedToRole(
                role_name=self._id.value,
                permission=permission.value,
            )
        )

    def remove_permission(self, permission: Permission) -> None:
        self._ensure_permission_granted(permission)

        self._permissions.discard(permission)

        self._record_event(
            PermissionRemovedFromRole(
                role_name=self._id.value,
                permission=permission.value,
            )
        )

    def change_description(self, new_description: RoleDescription) -> None:
        if new_description == self._description:
            return

        old_description = self._description
        self._description = new_description

        self._record_event(
            RoleDescriptionChanged(
                role_name=self._id.value,
                old_description=old_description.value,
                new_description=new_description.value,
            )
        )

    # --- Queries ---

    def grants(self, permission: Permission) -> bool:
        return permission in self._permissions

    # --- Class helpers ---

    @classmethod
    def collect_permissions(cls, roles: Iterable[Role]) -> frozenset[Permission]:
        return frozenset(perm for role in roles for perm in role.permissions)

    @classmethod
    def collect_role_names(cls, roles: Iterable[Role]) -> frozenset[RoleName]:
        return frozenset(role.name for role in roles)

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.events.role_events import (
    PermissionAddedToRole,
    PermissionRemovedFromRole,
    RoleCreated,
    RoleDescriptionChanged,
    RoleRenamed,
)
from pydentity.domain.models.base import AggregateRoot
from pydentity.domain.models.exceptions import (
    PermissionAlreadyGrantedError,
    PermissionNotGrantedError,
)
from pydentity.domain.models.value_objects import RoleDescription, RoleId, RoleName

if TYPE_CHECKING:
    from pydentity.domain.models.value_objects import Permission


class Role(AggregateRoot[RoleId]):
    def __init__(
        self,
        *,
        role_id: RoleId,
        name: RoleName,
        description: RoleDescription,
        permissions: set[Permission],
    ) -> None:
        super().__init__()
        self._id = role_id
        self._name = name
        self._description = description
        self._permissions = set(permissions)

    @classmethod
    def create(
        cls,
        role_id: RoleId,
        name: RoleName,
        description: RoleDescription,
    ) -> Role:
        role = cls(
            role_id=role_id,
            name=name,
            description=description,
            permissions=set(),
        )

        role._record_event(
            RoleCreated(
                role_id=role_id.value,
                name=role._name.value,
                description=description.value,
            )
        )
        return role

    @classmethod
    def _reconstitute(
        cls,
        role_id: RoleId,
        name: RoleName,
        description: RoleDescription,
        permissions: set[Permission],
    ) -> Role:
        return cls(
            role_id=role_id,
            name=name,
            description=description,
            permissions=permissions,
        )

    # --- Read-only properties ---

    @property
    def name(self) -> RoleName:
        return self._name

    @property
    def description(self) -> RoleDescription:
        return self._description

    @property
    def permissions(self) -> frozenset[Permission]:
        return frozenset(self._permissions)

    # --- Commands ---

    def add_permission(self, permission: Permission) -> None:
        if permission in self._permissions:
            raise PermissionAlreadyGrantedError(
                permission=permission, role_name=self._name.value
            )

        self._permissions.add(permission)

        self._record_event(
            PermissionAddedToRole(
                role_id=self._id.value,
                resource=permission.resource,
                action=permission.action,
            )
        )

    def remove_permission(self, permission: Permission) -> None:
        if permission not in self._permissions:
            raise PermissionNotGrantedError(
                permission=permission, role_name=self._name.value
            )

        self._permissions.discard(permission)

        self._record_event(
            PermissionRemovedFromRole(
                role_id=self._id.value,
                resource=permission.resource,
                action=permission.action,
            )
        )

    def rename(self, new_name: RoleName) -> None:
        if new_name == self._name:
            return

        old_name = self._name
        self._name = new_name

        self._record_event(
            RoleRenamed(
                role_id=self._id.value,
                old_name=old_name.value,
                new_name=self._name.value,
            )
        )

    def change_description(self, new_description: RoleDescription) -> None:
        if new_description == self._description:
            return

        old_description = self._description
        self._description = new_description

        self._record_event(
            RoleDescriptionChanged(
                role_id=self._id.value,
                old_description=old_description.value,
                new_description=new_description.value,
            )
        )

    # --- Queries ---

    def grants(self, permission: Permission) -> bool:
        return permission in self._permissions

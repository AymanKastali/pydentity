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
    RoleNameBlankError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.events.base import DomainEvent
    from pydentity.domain.models.value_objects import Permission, RoleId


class Role(AggregateRoot):
    def __init__(
        self,
        *,
        role_id: RoleId,
        name: str,
        description: str,
        permissions: set[Permission],
        created_at: datetime,
    ) -> None:
        self._id = role_id
        self._name = name
        self._description = description
        self._permissions = set(permissions)
        self._created_at = created_at
        self._events: list[DomainEvent] = []

    @staticmethod
    def create(
        role_id: RoleId,
        name: str,
        description: str,
        created_at: datetime,
    ) -> Role:
        if not name.strip():
            raise RoleNameBlankError("Role name cannot be blank")

        role = Role(
            role_id=role_id,
            name=name.strip(),
            description=description,
            permissions=set(),
            created_at=created_at,
        )

        role._record_event(
            RoleCreated(
                role_id=role_id.value,
                name=role._name,
            )
        )
        return role

    @staticmethod
    def _reconstitute(
        role_id: RoleId,
        name: str,
        description: str,
        permissions: set[Permission],
        created_at: datetime,
    ) -> Role:
        return Role(
            role_id=role_id,
            name=name,
            description=description,
            permissions=permissions,
            created_at=created_at,
        )

    # --- Read-only properties ---

    @property
    def id(self) -> RoleId:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def permissions(self) -> frozenset[Permission]:
        return frozenset(self._permissions)

    @property
    def created_at(self) -> datetime:
        return self._created_at

    # --- Commands ---

    def add_permission(self, permission: Permission) -> None:
        if permission in self._permissions:
            raise PermissionAlreadyGrantedError(
                f"Permission ({permission.resource}, {permission.action}) "
                f"is already granted to role {self._name!r}"
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
                f"Permission ({permission.resource}, {permission.action}) "
                f"is not granted to role {self._name!r}"
            )

        self._permissions.discard(permission)

        self._record_event(
            PermissionRemovedFromRole(
                role_id=self._id.value,
                resource=permission.resource,
                action=permission.action,
            )
        )

    def rename(self, new_name: str) -> None:
        if not new_name.strip():
            raise RoleNameBlankError("Role name cannot be blank")

        old_name = self._name
        self._name = new_name.strip()

        self._record_event(
            RoleRenamed(
                role_id=self._id.value,
                old_name=old_name,
                new_name=self._name,
            )
        )

    def change_description(self, new_description: str) -> None:
        self._description = new_description

        self._record_event(RoleDescriptionChanged(role_id=self._id.value))

    # --- Queries ---

    def grants(self, permission: Permission) -> bool:
        return permission in self._permissions

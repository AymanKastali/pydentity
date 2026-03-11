from __future__ import annotations

from dataclasses import dataclass

from pydentity.domain.events.base import DomainEvent


@dataclass(frozen=True, slots=True)
class RoleCreated(DomainEvent):
    role_name: str
    description: str


@dataclass(frozen=True, slots=True)
class RoleDescriptionChanged(DomainEvent):
    role_name: str
    old_description: str
    new_description: str


@dataclass(frozen=True, slots=True)
class PermissionAddedToRole(DomainEvent):
    role_name: str
    permission: str


@dataclass(frozen=True, slots=True)
class PermissionRemovedFromRole(DomainEvent):
    role_name: str
    permission: str

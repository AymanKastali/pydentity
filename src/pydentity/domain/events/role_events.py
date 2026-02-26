from __future__ import annotations

from dataclasses import dataclass

from pydentity.domain.events.base import DomainEvent


@dataclass(frozen=True, slots=True)
class RoleCreated(DomainEvent):
    role_id: str
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class RoleRenamed(DomainEvent):
    role_id: str
    old_name: str
    new_name: str


@dataclass(frozen=True, slots=True)
class RoleDescriptionChanged(DomainEvent):
    role_id: str
    old_description: str
    new_description: str


@dataclass(frozen=True, slots=True)
class PermissionAddedToRole(DomainEvent):
    role_id: str
    resource: str
    action: str


@dataclass(frozen=True, slots=True)
class PermissionRemovedFromRole(DomainEvent):
    role_id: str
    resource: str
    action: str

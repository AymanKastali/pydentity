from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CreateRoleInput:
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class CreateRoleOutput:
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class ChangeRoleDescriptionInput:
    role_name: str
    new_description: str


@dataclass(frozen=True, slots=True)
class AddPermissionToRoleInput:
    role_name: str
    resource: str
    action: str


@dataclass(frozen=True, slots=True)
class RemovePermissionFromRoleInput:
    role_name: str
    resource: str
    action: str


@dataclass(frozen=True, slots=True)
class AssignRoleToUserInput:
    user_id: str
    role_name: str


@dataclass(frozen=True, slots=True)
class RevokeRoleFromUserInput:
    user_id: str
    role_name: str

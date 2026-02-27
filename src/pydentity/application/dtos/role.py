from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CreateRoleInput:
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class CreateRoleOutput:
    role_id: str
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class RenameRoleInput:
    role_id: str
    new_name: str


@dataclass(frozen=True, slots=True)
class ChangeRoleDescriptionInput:
    role_id: str
    new_description: str


@dataclass(frozen=True, slots=True)
class AddPermissionToRoleInput:
    role_id: str
    resource: str
    action: str


@dataclass(frozen=True, slots=True)
class RemovePermissionFromRoleInput:
    role_id: str
    resource: str
    action: str


@dataclass(frozen=True, slots=True)
class AssignRoleToUserInput:
    user_id: str
    role_id: str


@dataclass(frozen=True, slots=True)
class RevokeRoleFromUserInput:
    user_id: str
    role_id: str

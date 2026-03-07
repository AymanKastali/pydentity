from __future__ import annotations

from pydantic import BaseModel


class CreateRoleRequest(BaseModel):
    name: str
    description: str


class CreateRoleResponse(BaseModel):
    role_id: str
    name: str
    description: str


class RenameRoleRequest(BaseModel):
    new_name: str


class ChangeRoleDescriptionRequest(BaseModel):
    new_description: str


class PermissionRequest(BaseModel):
    resource: str
    action: str


class AssignRoleRequest(BaseModel):
    user_id: str


class RevokeRoleRequest(BaseModel):
    user_id: str

from __future__ import annotations

from pydantic import BaseModel, Field


class CreateRoleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=500)


class CreateRoleResponse(BaseModel):
    name: str
    description: str


class ChangeRoleDescriptionRequest(BaseModel):
    new_description: str = Field(min_length=1, max_length=500)


class PermissionRequest(BaseModel):
    resource: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)


class AssignRoleRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=255)


class RevokeRoleRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=255)

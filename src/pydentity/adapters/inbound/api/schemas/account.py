from __future__ import annotations

from pydantic import BaseModel


class ChangeEmailRequest(BaseModel):
    user_id: str
    new_email: str


class SuspendUserRequest(BaseModel):
    user_id: str
    reason: str


class ReactivateUserRequest(BaseModel):
    user_id: str


class DeactivateUserRequest(BaseModel):
    user_id: str

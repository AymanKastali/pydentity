from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class ChangeEmailRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=255)
    new_email: EmailStr


class SuspendUserRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=500)


class ReactivateUserRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=255)


class DeactivateUserRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=255)

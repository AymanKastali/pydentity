from __future__ import annotations

from pydantic import BaseModel


class RequestPasswordResetRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    user_id: str
    token: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    user_id: str
    current_password: str
    new_password: str

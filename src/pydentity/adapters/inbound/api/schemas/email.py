from __future__ import annotations

from pydantic import BaseModel


class VerifyEmailRequest(BaseModel):
    user_id: str
    token: str


class ResendVerificationRequest(BaseModel):
    user_id: str

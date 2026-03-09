from __future__ import annotations

from pydantic import BaseModel


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    user_id: str

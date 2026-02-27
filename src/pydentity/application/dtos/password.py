from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RequestPasswordResetInput:
    email: str


@dataclass(frozen=True, slots=True)
class ResetPasswordInput:
    user_id: str
    token: str
    new_password: str


@dataclass(frozen=True, slots=True)
class ChangePasswordInput:
    user_id: str
    current_password: str
    new_password: str

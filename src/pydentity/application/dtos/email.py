from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VerifyEmailInput:
    user_id: str
    token: str


@dataclass(frozen=True, slots=True)
class ReissueVerificationTokenInput:
    user_id: str

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VerifyEmailInput:
    token: str


@dataclass(frozen=True, slots=True)
class ReissueVerificationTokenInput:
    user_id: str

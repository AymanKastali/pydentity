from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ChangeEmailInput:
    user_id: str
    new_email: str


@dataclass(frozen=True, slots=True)
class SuspendUserInput:
    user_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ReactivateUserInput:
    user_id: str


@dataclass(frozen=True, slots=True)
class DeactivateUserInput:
    user_id: str

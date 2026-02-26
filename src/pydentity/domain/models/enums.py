from __future__ import annotations

from enum import StrEnum, auto


class UserStatus(StrEnum):
    ACTIVE = auto()
    SUSPENDED = auto()
    DEACTIVATED = auto()


class SessionStatus(StrEnum):
    ACTIVE = auto()
    REVOKED = auto()

from __future__ import annotations

from enum import Enum


class UserStatus(Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DEACTIVATED = "DEACTIVATED"


class SessionStatus(Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"

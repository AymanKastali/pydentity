from __future__ import annotations

from enum import StrEnum, auto


class UserStatus(StrEnum):
    ACTIVE = auto()
    PENDING_VERIFICATION = auto()
    SUSPENDED = auto()
    DEACTIVATED = auto()


class SessionStatus(StrEnum):
    ACTIVE = auto()
    REVOKED = auto()


class DeviceStatus(StrEnum):
    ACTIVE = auto()
    REVOKED = auto()


class DevicePlatform(StrEnum):
    WEB = auto()
    MOBILE = auto()
    DESKTOP = auto()


class Resource(StrEnum):
    USERS = auto()
    ROLES = auto()
    SESSIONS = auto()
    DEVICES = auto()


class Action(StrEnum):
    READ = auto()
    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()
    SUSPEND = auto()
    REACTIVATE = auto()
    DEACTIVATE = auto()
    ASSIGN = auto()
    REVOKE = auto()

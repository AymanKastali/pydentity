from __future__ import annotations

from enum import StrEnum


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    SUSPENDED = "SUSPENDED"
    DEACTIVATED = "DEACTIVATED"


class SessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class DeviceStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class DevicePlatform(StrEnum):
    WEB = "WEB"
    MOBILE = "MOBILE"
    DESKTOP = "DESKTOP"


class Resource(StrEnum):
    USERS = "USERS"
    ROLES = "ROLES"
    SESSIONS = "SESSIONS"
    DEVICES = "DEVICES"


class Action(StrEnum):
    READ = "READ"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    SUSPEND = "SUSPEND"
    REACTIVATE = "REACTIVATE"
    DEACTIVATE = "DEACTIVATE"
    ASSIGN = "ASSIGN"
    REVOKE = "REVOKE"

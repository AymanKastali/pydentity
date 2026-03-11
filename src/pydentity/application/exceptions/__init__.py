from pydentity.application.exceptions.app import (
    ApplicationError,
    DeviceNotFoundError,
    EmailAlreadyRegisteredError,
    InsufficientPermissionsError,
    InvalidTokenError,
    PersistenceConsistencyError,
    RoleNotFoundError,
    SessionNotFoundError,
    UserNotFoundError,
)

__all__ = [
    "ApplicationError",
    "DeviceNotFoundError",
    "EmailAlreadyRegisteredError",
    "InsufficientPermissionsError",
    "InvalidTokenError",
    "PersistenceConsistencyError",
    "RoleNotFoundError",
    "SessionNotFoundError",
    "UserNotFoundError",
]

from pydentity.application.exceptions.app import (
    ApplicationError,
    EmailAlreadyRegisteredError,
    InsufficientPermissionsError,
    InvalidTokenError,
    PersistenceConsistencyError,
    ResourceNotFoundError,
)

__all__ = [
    "ApplicationError",
    "EmailAlreadyRegisteredError",
    "InsufficientPermissionsError",
    "InvalidTokenError",
    "PersistenceConsistencyError",
    "ResourceNotFoundError",
]

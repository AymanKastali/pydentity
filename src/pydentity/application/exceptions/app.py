from __future__ import annotations


class ApplicationError(Exception):
    """Base class for all application-layer errors."""


class UserNotFoundError(ApplicationError):
    def __init__(self, *, user_id: str) -> None:
        super().__init__(f"User not found: {user_id!r}")


class RoleNotFoundError(ApplicationError):
    def __init__(self, *, role_name: str) -> None:
        super().__init__(f"Role not found: {role_name!r}")


class EmailAlreadyRegisteredError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("Email address is already registered")


class InvalidTokenError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("The provided token is invalid or has expired.")


class InsufficientPermissionsError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("You do not have the required permissions for this action.")


class PersistenceConsistencyError(ApplicationError):
    def __init__(self, *, detail: str) -> None:
        super().__init__(f"Data consistency violation: {detail}")


class SessionNotFoundError(ApplicationError):
    def __init__(self, *, session_id: str) -> None:
        super().__init__(f"Session not found: {session_id!r}")


class DeviceNotFoundError(ApplicationError):
    def __init__(self, *, device_id: str) -> None:
        super().__init__(f"Device not found: {device_id!r}")

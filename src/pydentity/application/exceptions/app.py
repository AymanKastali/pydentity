from __future__ import annotations


class ApplicationError(Exception):
    """Base class for all application-layer errors."""


class UserNotFoundError(ApplicationError):
    def __init__(self, *, user_id: str) -> None:
        super().__init__(f"User not found: {user_id!r}")


class RoleNotFoundError(ApplicationError):
    def __init__(self, *, role_id: str) -> None:
        super().__init__(f"Role not found: {role_id!r}")


class EmailAlreadyRegisteredError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("Email address is already registered")


class InvalidTokenError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("The provided token is invalid or has expired.")

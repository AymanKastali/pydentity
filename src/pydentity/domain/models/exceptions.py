from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from pydentity.domain.models.enums import UserStatus
    from pydentity.domain.models.value_objects import Permission, RoleId, UserId


class DomainError(Exception):
    """Base class for all domain-layer errors."""


# --- User exceptions ---


class PasswordPolicyViolationError(DomainError):
    """Raised when a password does not meet the required
    policy constraints.
    """

    def __init__(
        self,
        *,
        violations: Sequence[str] | None = None,
    ) -> None:
        if violations is not None:
            message = "; ".join(violations)
        else:
            message = "Password does not meet policy requirements"
        super().__init__(message)


class PasswordReuseError(DomainError):
    """Raised when a new password matches one in the recent
    password history.
    """

    def __init__(
        self,
        *,
        history_size: int | None = None,
    ) -> None:
        if history_size is not None:
            message = f"Cannot reuse any of the last {history_size} passwords"
        else:
            message = "Password was recently used and cannot be reused"
        super().__init__(message)


class AccountLockedError(DomainError):
    """Raised when an operation is attempted on a temporarily
    locked account.
    """

    def __init__(
        self,
        *,
        locked_until: datetime | None = None,
    ) -> None:
        if locked_until is not None:
            message = f"Account is locked until {locked_until.isoformat()}"
        else:
            message = (
                "Account is temporarily locked due to too many failed login attempts"
            )
        super().__init__(message)


class AccountNotActiveError(DomainError):
    """Raised when an operation requires an active account
    but the account is not in ACTIVE status.
    """

    def __init__(
        self,
        *,
        status: UserStatus | None = None,
    ) -> None:
        if status is not None:
            message = f"Account is not active (status={status.value})"
        else:
            message = "Account is not active"
        super().__init__(message)


class AccountAlreadyActiveError(DomainError):
    """Raised when reactivation is attempted on an account
    that is already in ACTIVE status.
    """

    def __init__(self) -> None:
        super().__init__("Account is already active")


class AccountDeactivatedError(DomainError):
    """Raised when an operation is attempted on a permanently
    deactivated account.
    """

    def __init__(self) -> None:
        super().__init__("Account has been permanently deactivated")


class AccountAlreadyDeactivatedError(DomainError):
    """Raised when deactivation is attempted on an account
    that is already deactivated.
    """

    def __init__(self) -> None:
        super().__init__("Account is already deactivated")


class EmailUnchangedError(DomainError):
    """Raised when a change-email operation is attempted
    with the same email address already on file.
    """

    def __init__(self) -> None:
        super().__init__("New email address is the same as the current one")


class EmailAlreadyVerifiedError(DomainError):
    """Raised when email verification is attempted but the
    email is already verified.
    """

    def __init__(self) -> None:
        super().__init__("Email address is already verified")


class VerificationTokenExpiredError(DomainError):
    """Raised when an email verification token has passed
    its expiry time.
    """

    def __init__(self) -> None:
        super().__init__("Email verification token has expired")


class VerificationTokenInvalidError(DomainError):
    """Raised when an email verification token does not match
    the stored token.
    """

    def __init__(self) -> None:
        super().__init__("Email verification token is invalid")


class VerificationTokenNotIssuedError(DomainError):
    """Raised when email verification is attempted but no
    verification token has been issued.
    """

    def __init__(self) -> None:
        super().__init__("No email verification token has been issued")


class ResetTokenExpiredError(DomainError):
    """Raised when a password reset token has passed its
    expiry time.
    """

    def __init__(self) -> None:
        super().__init__("Password reset token has expired")


class ResetTokenInvalidError(DomainError):
    """Raised when a password reset token does not match
    the stored token.
    """

    def __init__(self) -> None:
        super().__init__("Password reset token is invalid")


class ResetTokenNotIssuedError(DomainError):
    """Raised when a password reset is attempted but no
    reset token has been issued.
    """

    def __init__(self) -> None:
        super().__init__("No password reset token has been issued")


class InvalidCredentialsError(DomainError):
    """Raised when supplied credentials do not match the
    stored credentials.
    """

    def __init__(self) -> None:
        super().__init__("Invalid credentials")


# --- Session exceptions ---


class SessionRevokedError(DomainError):
    """Raised when an operation is attempted on a revoked
    session.
    """

    def __init__(self) -> None:
        super().__init__("Session has been revoked")


class SessionExpiredError(DomainError):
    """Raised when an operation is attempted on an expired
    session.
    """

    def __init__(self) -> None:
        super().__init__("Session has expired")


class RefreshTokenReuseDetectedError(DomainError):
    """Raised when a previously used refresh token is
    presented, indicating a potential token theft.
    """

    def __init__(self) -> None:
        super().__init__("Refresh token reuse detected — session revoked for security")


# --- User authorization exceptions ---


class RoleAlreadyAssignedError(DomainError):
    """Raised when a role is assigned to a user who already
    holds that role.
    """

    def __init__(
        self,
        *,
        role_id: RoleId | None = None,
        user_id: UserId | None = None,
    ) -> None:
        if role_id is not None and user_id is not None:
            message = (
                f"Role {role_id.value!r} is already assigned to user {user_id.value!r}"
            )
        else:
            message = "Role is already assigned to this user"
        super().__init__(message)


class RoleNotAssignedError(DomainError):
    """Raised when attempting to revoke a role that is not
    assigned to the user.
    """

    def __init__(
        self,
        *,
        role_id: RoleId | None = None,
        user_id: UserId | None = None,
    ) -> None:
        if role_id is not None and user_id is not None:
            message = (
                f"Role {role_id.value!r} is not assigned to user {user_id.value!r}"
            )
        else:
            message = "Role is not assigned to this user"
        super().__init__(message)


# --- Role exceptions ---


class PermissionAlreadyGrantedError(DomainError):
    """Raised when a permission is added to a role that
    already holds it.
    """

    def __init__(
        self,
        *,
        permission: Permission | None = None,
        role_name: str | None = None,
    ) -> None:
        if permission is not None and role_name is not None:
            message = (
                f"Permission ({permission.resource}, {permission.action}) "
                f"is already granted to role {role_name!r}"
            )
        else:
            message = "Permission is already granted to this role"
        super().__init__(message)


class PermissionNotGrantedError(DomainError):
    """Raised when attempting to remove a permission that is
    not granted to the role.
    """

    def __init__(
        self,
        *,
        permission: Permission | None = None,
        role_name: str | None = None,
    ) -> None:
        if permission is not None and role_name is not None:
            message = (
                f"Permission ({permission.resource}, {permission.action}) "
                f"is not granted to role {role_name!r}"
            )
        else:
            message = "Permission is not granted to this role"
        super().__init__(message)


# --- Value object validation exceptions ---


class EmptyValueError(DomainError):
    """Raised when a value object receives an empty value
    where a non-empty value is required.
    """

    def __init__(
        self,
        *,
        field_name: str,
    ) -> None:
        super().__init__(f"{field_name} cannot be empty")


class InvalidValueError(DomainError):
    """Raised when a value object receives a value that
    violates a domain constraint.
    """

    def __init__(
        self,
        *,
        field_name: str,
        reason: str,
    ) -> None:
        super().__init__(f"{field_name}: {reason}")


class InvalidEmailAddressError(DomainError):
    """Raised when an email address value object receives
    an invalid local part or domain.
    """

    def __init__(
        self,
        *,
        detail: str | None = None,
    ) -> None:
        if detail is not None:
            message = f"Invalid email address: {detail}"
        else:
            message = "Invalid email address"
        super().__init__(message)


# --- Policy validation exceptions ---


class InvalidPolicyValueError(DomainError):
    """Raised when a policy value object receives a value
    that violates its configuration constraints.
    """

    def __init__(
        self,
        *,
        field_name: str,
        reason: str,
    ) -> None:
        super().__init__(f"{field_name}: {reason}")

from __future__ import annotations


class DomainError(Exception):
    """Base class for all domain-layer errors."""


# --- User exceptions ---


class PasswordPolicyViolationError(DomainError):
    """Raised when a password does not meet the required
    policy constraints.
    """

    def __init__(
        self,
        message: str = "Password does not meet policy requirements",
    ) -> None:
        super().__init__(message)


class PasswordReuseError(DomainError):
    """Raised when a new password matches one in the recent
    password history.
    """

    def __init__(
        self,
        message: str = "Password was recently used and cannot be reused",
    ) -> None:
        super().__init__(message)


class AccountLockedError(DomainError):
    """Raised when an operation is attempted on a temporarily
    locked account.
    """

    def __init__(
        self,
        message: str = (
            "Account is temporarily locked due to too many failed login attempts"
        ),
    ) -> None:
        super().__init__(message)


class AccountNotActiveError(DomainError):
    """Raised when an operation requires an active account
    but the account is not in ACTIVE status.
    """

    def __init__(self, message: str = "Account is not active") -> None:
        super().__init__(message)


class AccountDeactivatedError(DomainError):
    """Raised when an operation is attempted on a permanently
    deactivated account.
    """

    def __init__(
        self,
        message: str = "Account has been permanently deactivated",
    ) -> None:
        super().__init__(message)


class EmailAlreadyVerifiedError(DomainError):
    """Raised when email verification is attempted but the
    email is already verified.
    """

    def __init__(
        self,
        message: str = "Email address is already verified",
    ) -> None:
        super().__init__(message)


class VerificationTokenExpiredError(DomainError):
    """Raised when an email verification token has passed
    its expiry time.
    """

    def __init__(
        self,
        message: str = "Email verification token has expired",
    ) -> None:
        super().__init__(message)


class VerificationTokenInvalidError(DomainError):
    """Raised when an email verification token does not match
    or was never issued.
    """

    def __init__(
        self,
        message: str = "Email verification token is invalid",
    ) -> None:
        super().__init__(message)


class ResetTokenExpiredError(DomainError):
    """Raised when a password reset token has passed its
    expiry time.
    """

    def __init__(
        self,
        message: str = "Password reset token has expired",
    ) -> None:
        super().__init__(message)


class ResetTokenInvalidError(DomainError):
    """Raised when a password reset token does not match
    or was never issued.
    """

    def __init__(
        self,
        message: str = "Password reset token is invalid",
    ) -> None:
        super().__init__(message)


class InvalidCredentialsError(DomainError):
    """Raised when supplied credentials do not match the
    stored credentials.
    """

    def __init__(self, message: str = "Invalid credentials") -> None:
        super().__init__(message)


class EmailNotVerifiedError(DomainError):
    """Raised when an operation requires a verified email
    but the email is unverified.
    """

    def __init__(
        self,
        message: str = "Email address has not been verified",
    ) -> None:
        super().__init__(message)


# --- Session exceptions ---


class SessionRevokedError(DomainError):
    """Raised when an operation is attempted on a revoked
    session.
    """

    def __init__(self, message: str = "Session has been revoked") -> None:
        super().__init__(message)


class SessionExpiredError(DomainError):
    """Raised when an operation is attempted on an expired
    session.
    """

    def __init__(self, message: str = "Session has expired") -> None:
        super().__init__(message)


class RefreshTokenMismatchError(DomainError):
    """Raised when a presented refresh token does not match
    the stored hash.
    """

    def __init__(self, message: str = "Refresh token does not match") -> None:
        super().__init__(message)


class RefreshTokenReuseDetectedError(DomainError):
    """Raised when a previously used refresh token is
    presented, indicating a potential token theft.
    """

    def __init__(
        self,
        message: str = "Refresh token reuse detected — session revoked for security",
    ) -> None:
        super().__init__(message)


# --- User authorization exceptions ---


class RoleAlreadyAssignedError(DomainError):
    """Raised when a role is assigned to a user who already
    holds that role.
    """

    def __init__(
        self,
        message: str = "Role is already assigned to this user",
    ) -> None:
        super().__init__(message)


class RoleNotAssignedError(DomainError):
    """Raised when attempting to revoke a role that is not
    assigned to the user.
    """

    def __init__(
        self,
        message: str = "Role is not assigned to this user",
    ) -> None:
        super().__init__(message)


# --- Role exceptions ---


class PermissionAlreadyGrantedError(DomainError):
    """Raised when a permission is added to a role that
    already holds it.
    """

    def __init__(
        self,
        message: str = "Permission is already granted to this role",
    ) -> None:
        super().__init__(message)


class PermissionNotGrantedError(DomainError):
    """Raised when attempting to remove a permission that is
    not granted to the role.
    """

    def __init__(
        self,
        message: str = "Permission is not granted to this role",
    ) -> None:
        super().__init__(message)


class RoleNameBlankError(DomainError):
    """Raised when a role name is empty or blank."""

    def __init__(self, message: str = "Role name cannot be blank") -> None:
        super().__init__(message)

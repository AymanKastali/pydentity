from pydentity.shared_kernel import DomainError


class AccountNotActiveError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account is not active.")


class AccountNotUnverifiedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account is not unverified.")


class AccountNotLockedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account is not locked.")


class AccountUnverifiedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account has not been verified.")


class AccountAlreadySuspendedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account is already suspended.")


class AccountAlreadyClosedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account is already closed.")


class PasswordReuseError(DomainError):
    def __init__(self) -> None:
        super().__init__("Password was recently used and cannot be reused.")


class DuplicateTOTPSecretError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account already has a TOTP secret.")


class TOTPSecretNotFoundError(DomainError):
    def __init__(self) -> None:
        super().__init__("Account does not have a TOTP secret.")


class CannotRemoveCredentialError(DomainError):
    def __init__(self) -> None:
        super().__init__("Cannot remove credential while MFA requires it.")


class MFAAlreadyEnabledError(DomainError):
    def __init__(self) -> None:
        super().__init__("MFA is already enabled.")


class MFANotEnabledError(DomainError):
    def __init__(self) -> None:
        super().__init__("MFA is not enabled.")


class MFARequiresCredentialError(DomainError):
    def __init__(self) -> None:
        super().__init__("MFA requires at least one non-password credential.")


class RecoveryCodeNotFoundError(DomainError):
    def __init__(self) -> None:
        super().__init__("Recovery code not found or already used.")


class EmailAlreadyTakenError(DomainError):
    def __init__(self) -> None:
        super().__init__("Email address is already associated with an account.")


class PasswordPolicyViolationError(DomainError):
    def __init__(self, message: str) -> None:
        super().__init__(message)

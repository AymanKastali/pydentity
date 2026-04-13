from pydentity.authentication.domain.account.value_objects import (
    AccountStatus,
    Email,
)
from pydentity.shared_kernel.building_blocks import DomainError


class AccountError(DomainError):
    pass


class AccountNotActiveError(AccountError):
    def __init__(self, current_status: AccountStatus) -> None:
        super().__init__(f"Account must be active, but status is {current_status}.")


class AccountNotPendingVerificationError(AccountError):
    def __init__(self, current_status: AccountStatus) -> None:
        super().__init__(
            f"Account must be pending verification, but status is {current_status}."
        )


class AccountNotLockableError(AccountError):
    def __init__(self, current_status: AccountStatus) -> None:
        super().__init__(f"Account cannot be locked from status {current_status}.")


class AccountNotUnlockableError(AccountError):
    def __init__(self, current_status: AccountStatus) -> None:
        super().__init__(f"Account cannot be unlocked from status {current_status}.")


class InvalidCredentialsError(AccountError):
    def __init__(self) -> None:
        super().__init__("Invalid credentials.")


class PasswordAlreadyUsedError(AccountError):
    def __init__(self) -> None:
        super().__init__("Password has been used previously.")


class PasswordCompromisedError(AccountError):
    def __init__(self) -> None:
        super().__init__("Password appears in known data breaches.")


class PasswordPolicyViolationError(AccountError):
    def __init__(self, min_length: int, max_length: int) -> None:
        super().__init__(
            f"Password must be between {min_length} and {max_length} characters."
        )


class InvalidEmailError(AccountError):
    def __init__(self, email: Email) -> None:
        super().__init__(f"Email {email.value} is not a valid email address.")


class DuplicateEmailError(AccountError):
    def __init__(self, email: Email) -> None:
        super().__init__(f"Email {email.value} is already in use.")

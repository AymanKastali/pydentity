from typing import TYPE_CHECKING

from pydentity.domain.base import DomainError

if TYPE_CHECKING:
    from uuid import UUID


class AccountNotFoundError(DomainError):
    def __init__(self, account_id: UUID) -> None:
        super().__init__(f"Account not found: {account_id}")
        self.account_id = account_id


class AccountAlreadyExistsError(DomainError):
    def __init__(self, email: str) -> None:
        super().__init__(f"Account already exists with email: {email}")
        self.email = email


class AccountNotActiveError(DomainError):
    def __init__(self, account_id: UUID) -> None:
        super().__init__(f"Account is not active: {account_id}")
        self.account_id = account_id


class InvalidCredentialsError(DomainError):
    def __init__(self) -> None:
        super().__init__("Invalid credentials")


class EmailAlreadyVerifiedError(DomainError):
    def __init__(self, account_id: UUID) -> None:
        super().__init__(f"Email already verified: {account_id}")
        self.account_id = account_id


class InvalidVerificationTokenError(DomainError):
    def __init__(self, account_id: UUID) -> None:
        super().__init__(f"Invalid verification token: {account_id}")
        self.account_id = account_id

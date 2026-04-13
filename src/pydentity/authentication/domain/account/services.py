from pydentity.authentication.domain.account.aggregate import Account
from pydentity.authentication.domain.account.errors import (
    DuplicateEmailError,
    InvalidCredentialsError,
    InvalidEmailError,
    PasswordAlreadyUsedError,
    PasswordCompromisedError,
    PasswordPolicyViolationError,
)
from pydentity.authentication.domain.account.interfaces import (
    CompromisedPasswordChecker,
    EmailVerifier,
    PasswordHasher,
    PasswordVerifier,
)
from pydentity.authentication.domain.account.repository import AccountRepository
from pydentity.authentication.domain.account.value_objects import (
    CredentialId,
    Email,
    HashedPassword,
    PasswordPolicy,
    RawPassword,
)
from pydentity.shared_kernel.value_objects import AccountId


class PreventDuplicateEmail:
    def __init__(self, repository: AccountRepository) -> None:
        self._repository = repository

    async def ensure_unique(self, email: Email) -> None:
        if await self._repository.exists_by_email(email):
            raise DuplicateEmailError(email)


class ChangeAccountPassword:
    def __init__(
        self,
        verifier: PasswordVerifier,
        hasher: PasswordHasher,
        compromised_checker: CompromisedPasswordChecker,
    ) -> None:
        self._verifier = verifier
        self._hasher = hasher
        self._compromised_checker = compromised_checker

    def change_password(
        self,
        current_password: RawPassword,
        new_password: RawPassword,
        hashed_password: HashedPassword,
        password_history: list[HashedPassword],
        policy: PasswordPolicy,
    ) -> HashedPassword:
        self._guard_current_password_matches(current_password, hashed_password)
        self._guard_password_meets_policy(new_password, policy)
        self._guard_password_not_compromised(new_password)
        self._guard_password_not_reused(new_password, hashed_password, password_history)
        return self._hasher.hash(new_password)

    def _guard_current_password_matches(
        self, password: RawPassword, hashed_password: HashedPassword
    ) -> None:
        if not self._verifier.verify(password, hashed_password):
            raise InvalidCredentialsError()

    def _guard_password_meets_policy(
        self, password: RawPassword, policy: PasswordPolicy
    ) -> None:
        if not (policy.min_length <= len(password.value) <= policy.max_length):
            raise PasswordPolicyViolationError(policy.min_length, policy.max_length)

    def _guard_password_not_compromised(self, password: RawPassword) -> None:
        if self._compromised_checker.is_compromised(password):
            raise PasswordCompromisedError()

    def _guard_password_not_reused(
        self,
        new_password: RawPassword,
        hashed_password: HashedPassword,
        password_history: list[HashedPassword],
    ) -> None:
        if self._verifier.verify(new_password, hashed_password):
            raise PasswordAlreadyUsedError()
        for old_hash in password_history:
            if self._verifier.verify(new_password, old_hash):
                raise PasswordAlreadyUsedError()


class AuthenticateAccount:
    def __init__(
        self, repository: AccountRepository, verifier: PasswordVerifier
    ) -> None:
        self._repository = repository
        self._verifier = verifier

    async def authenticate(self, email: Email, password: RawPassword) -> Account:
        account = await self._guard_account_exists(email)
        self._guard_credentials_match(password, account.credentials.hashed_password)
        return account

    async def _guard_account_exists(self, email: Email) -> Account:
        account = await self._repository.find_by_email(email)
        if account is None:
            raise InvalidCredentialsError()
        return account

    def _guard_credentials_match(
        self, password: RawPassword, hashed_password: HashedPassword
    ) -> None:
        if not self._verifier.verify(password, hashed_password):
            raise InvalidCredentialsError()


class ChangeAccountEmail:
    def __init__(
        self, email_verifier: EmailVerifier, duplicate_checker: PreventDuplicateEmail
    ) -> None:
        self._email_verifier = email_verifier
        self._duplicate_checker = duplicate_checker

    async def change_email(self, new_email: Email) -> None:
        self._guard_email_is_valid(new_email)
        await self._duplicate_checker.ensure_unique(new_email)

    def _guard_email_is_valid(self, email: Email) -> None:
        if not self._email_verifier.is_valid(email):
            raise InvalidEmailError(email)


class RegisterAccount:
    def __init__(
        self,
        email_verifier: EmailVerifier,
        hasher: PasswordHasher,
        compromised_checker: CompromisedPasswordChecker,
        duplicate_checker: PreventDuplicateEmail,
    ) -> None:
        self._email_verifier = email_verifier
        self._hasher = hasher
        self._compromised_checker = compromised_checker
        self._duplicate_checker = duplicate_checker

    async def register(
        self,
        account_id: AccountId,
        credential_id: CredentialId,
        email: Email,
        password: RawPassword,
        policy: PasswordPolicy,
    ) -> Account:
        self._guard_email_is_valid(email)
        self._guard_password_meets_policy(password, policy)
        self._guard_password_not_compromised(password)
        await self._duplicate_checker.ensure_unique(email)
        hashed_password = self._hasher.hash(password)
        return Account.create(account_id, credential_id, email, hashed_password)

    def _guard_email_is_valid(self, email: Email) -> None:
        if not self._email_verifier.is_valid(email):
            raise InvalidEmailError(email)

    def _guard_password_meets_policy(
        self, password: RawPassword, policy: PasswordPolicy
    ) -> None:
        if not (policy.min_length <= len(password.value) <= policy.max_length):
            raise PasswordPolicyViolationError(policy.min_length, policy.max_length)

    def _guard_password_not_compromised(self, password: RawPassword) -> None:
        if self._compromised_checker.is_compromised(password):
            raise PasswordCompromisedError()

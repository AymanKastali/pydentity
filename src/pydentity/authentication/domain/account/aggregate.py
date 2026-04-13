from typing import Self

from pydentity.authentication.domain.account.errors import (
    AccountNotActiveError,
    AccountNotLockableError,
    AccountNotPendingVerificationError,
    AccountNotUnlockableError,
)
from pydentity.authentication.domain.account.events import (
    AccountClosed,
    AccountLocked,
    AccountRegistered,
    AccountSuspended,
    AccountUnlocked,
    EmailChanged,
    EmailVerified,
    LoginFailed,
    LoginSucceeded,
    PasswordChanged,
)
from pydentity.authentication.domain.account.value_objects import (
    AccountStatus,
    CredentialId,
    Email,
    FailedAttemptCount,
    HashedPassword,
    LockoutPolicy,
    LockReason,
    UnlockReason,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot, Entity
from pydentity.shared_kernel.value_objects import AccountId


class EmailPasswordCredential(Entity[CredentialId]):
    def __init__(
        self,
        credential_id: CredentialId,
        email: Email,
        hashed_password: HashedPassword,
        password_history: list[HashedPassword],
    ) -> None:
        super().__init__(credential_id)
        self._email: Email = email
        self._hashed_password: HashedPassword = hashed_password
        self._password_history: list[HashedPassword] = list(password_history)

    def change_password(self, new_hash: HashedPassword, max_history: int) -> None:
        self._rotate_password_history(max_history)
        self._hashed_password = new_hash

    def _rotate_password_history(self, max_history: int) -> None:
        self._password_history.append(self._hashed_password)
        if len(self._password_history) > max_history:
            self._password_history = self._password_history[-max_history:]

    def change_email(self, new_email: Email) -> None:
        self._email = new_email

    @property
    def email(self) -> Email:
        return self._email

    @property
    def hashed_password(self) -> HashedPassword:
        return self._hashed_password

    @property
    def password_history(self) -> list[HashedPassword]:
        return list(self._password_history)


class Account(AggregateRoot[AccountId]):
    def __init__(
        self,
        account_id: AccountId,
        status: AccountStatus,
        credentials: EmailPasswordCredential,
        failed_attempt_count: FailedAttemptCount,
    ) -> None:
        super().__init__(account_id)
        self._status: AccountStatus = status
        self._credentials: EmailPasswordCredential = credentials
        self._failed_attempt_count: FailedAttemptCount = failed_attempt_count

    @classmethod
    def create(
        cls,
        account_id: AccountId,
        credential_id: CredentialId,
        email: Email,
        hashed_password: HashedPassword,
    ) -> Self:
        credential = EmailPasswordCredential(
            credential_id=credential_id,
            email=email,
            hashed_password=hashed_password,
            password_history=[],
        )
        account = cls(
            account_id=account_id,
            status=AccountStatus.PENDING_VERIFICATION,
            credentials=credential,
            failed_attempt_count=FailedAttemptCount(0),
        )
        account._record_account_registered()
        return account

    def _record_account_registered(self) -> None:
        self.record_event(
            AccountRegistered(account_id=self._id, email=self._credentials.email)
        )

    def record_login_success(self) -> None:
        self._guard_status_is_active()
        self._reset_failed_attempt_count()
        self._record_login_succeeded()

    def _record_login_succeeded(self) -> None:
        self.record_event(LoginSucceeded(account_id=self._id))

    def record_login_failure(self, lockout_policy: LockoutPolicy) -> None:
        self._guard_status_is_active()
        self._handle_failed_login(lockout_policy)

    def _handle_failed_login(self, lockout_policy: LockoutPolicy) -> None:
        self._increment_failed_attempt_count()
        self._record_login_failed()
        if self._lockout_threshold_reached(lockout_policy):
            self.lock(LockReason.THRESHOLD)

    def _lockout_threshold_reached(self, lockout_policy: LockoutPolicy) -> bool:
        return self._failed_attempt_count.value >= lockout_policy.max_failed_attempts

    def _record_login_failed(self) -> None:
        self.record_event(
            LoginFailed(
                account_id=self._id, failed_attempt_count=self._failed_attempt_count
            )
        )

    def verify_email(self) -> None:
        self._guard_status_is_pending_verification()
        self._mark_as_active()
        self._record_email_verified()

    def _guard_status_is_pending_verification(self) -> None:
        if self._status is not AccountStatus.PENDING_VERIFICATION:
            raise AccountNotPendingVerificationError(self._status)

    def _record_email_verified(self) -> None:
        self.record_event(EmailVerified(account_id=self._id))

    def change_password(self, new_hash: HashedPassword, max_history: int) -> None:
        self._guard_status_is_active()
        self._credentials.change_password(new_hash, max_history)
        self._record_password_changed()

    def _record_password_changed(self) -> None:
        self.record_event(PasswordChanged(account_id=self._id))

    def change_email(self, new_email: Email) -> None:
        self._guard_status_is_active()
        old_email = self._credentials.email
        self._credentials.change_email(new_email)
        self._record_email_changed(old_email, new_email)

    def _record_email_changed(self, old_email: Email, new_email: Email) -> None:
        self.record_event(
            EmailChanged(account_id=self._id, old_email=old_email, new_email=new_email)
        )

    def lock(self, reason: LockReason) -> None:
        self._guard_status_is_lockable()
        self._mark_as_locked()
        self._record_account_locked(reason)

    def _guard_status_is_lockable(self) -> None:
        if self._status is not AccountStatus.ACTIVE:
            raise AccountNotLockableError(self._status)

    def unlock(self, reason: UnlockReason) -> None:
        self._guard_status_is_unlockable()
        self._mark_as_active()
        self._reset_failed_attempt_count()
        self._record_account_unlocked(reason)

    def _guard_status_is_unlockable(self) -> None:
        if self._status is not AccountStatus.LOCKED:
            raise AccountNotUnlockableError(self._status)

    def _record_account_unlocked(self, reason: UnlockReason) -> None:
        self.record_event(AccountUnlocked(account_id=self._id, reason=reason))

    def suspend(self) -> None:
        self._guard_status_is_active()
        self._mark_as_suspended()
        self._record_account_suspended()

    def _mark_as_suspended(self) -> None:
        self._status = AccountStatus.SUSPENDED

    def _record_account_suspended(self) -> None:
        self.record_event(AccountSuspended(account_id=self._id))

    def close(self) -> None:
        self._guard_status_is_active()
        self._mark_as_closed()
        self._record_account_closed()

    def _mark_as_closed(self) -> None:
        self._status = AccountStatus.CLOSED

    def _record_account_closed(self) -> None:
        self.record_event(AccountClosed(account_id=self._id))

    def _guard_status_is_active(self) -> None:
        if self._status is not AccountStatus.ACTIVE:
            raise AccountNotActiveError(self._status)

    def _mark_as_active(self) -> None:
        self._status = AccountStatus.ACTIVE

    def _mark_as_locked(self) -> None:
        self._status = AccountStatus.LOCKED

    def _increment_failed_attempt_count(self) -> None:
        self._failed_attempt_count = FailedAttemptCount(
            self._failed_attempt_count.value + 1
        )

    def _reset_failed_attempt_count(self) -> None:
        self._failed_attempt_count = FailedAttemptCount(0)

    def _record_account_locked(self, reason: LockReason) -> None:
        self.record_event(AccountLocked(account_id=self._id, reason=reason))

    @property
    def status(self) -> AccountStatus:
        return self._status

    @property
    def credentials(self) -> EmailPasswordCredential:
        return self._credentials

    @property
    def failed_attempt_count(self) -> FailedAttemptCount:
        return self._failed_attempt_count

    @property
    def email(self) -> Email:
        return self._credentials.email

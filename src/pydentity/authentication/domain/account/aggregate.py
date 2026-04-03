from typing import TYPE_CHECKING

from pydentity.authentication.domain.account.errors import (
    CannotRemoveCredentialError,
    DuplicateTOTPSecretError,
    MFAAlreadyEnabledError,
    MFANotEnabledError,
    MFARequiresCredentialError,
    TOTPSecretNotFoundError,
)
from pydentity.authentication.domain.account.events import (
    AccountClosed,
    AccountLocked,
    AccountRegistered,
    AccountSuspended,
    AccountUnlocked,
    EmailVerificationRequested,
    EmailVerified,
    MFADisabled,
    MFAEnabled,
    PasswordChanged,
    PasswordResetCompleted,
    RecoveryCodeConsumed,
    RecoveryCodesGenerated,
    TOTPSecretAdded,
    TOTPSecretRemoved,
)
from pydentity.authentication.domain.account.value_objects import (
    AccountStatus,
    EmailAddress,
    EncryptedTOTPSecret,
    HashedPassword,
    HashedPasswordHistory,
    HashedRecoveryCode,
    HashedRecoveryCodeSet,
    LockoutPolicy,
    LockoutState,
    LockReason,
    PasswordPolicy,
    UnlockReason,
)
from pydentity.shared_kernel import AccountId, AggregateRoot, IdentityId

if TYPE_CHECKING:
    from datetime import datetime


class Account(AggregateRoot[AccountId]):
    def __init__(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        email: EmailAddress,
        status: AccountStatus,
        hashed_password: HashedPassword,
        password_history: HashedPasswordHistory,
        totp_secret: EncryptedTOTPSecret | None,
        recovery_code_set: HashedRecoveryCodeSet,
        is_mfa_enabled: bool,
        lockout_state: LockoutState,
    ) -> None:
        super().__init__(account_id)
        self._identity_id: IdentityId = identity_id
        self._email: EmailAddress = email
        self._status: AccountStatus = status
        self._hashed_password: HashedPassword = hashed_password
        self._password_history: HashedPasswordHistory = password_history
        self._totp_secret: EncryptedTOTPSecret | None = totp_secret
        self._recovery_code_set: HashedRecoveryCodeSet = recovery_code_set
        self._is_mfa_enabled: bool = is_mfa_enabled
        self._lockout_state: LockoutState = lockout_state

    # --- Creation ---

    @classmethod
    def register(
        cls,
        account_id: AccountId,
        identity_id: IdentityId,
        email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ) -> Account:
        account = cls(
            account_id=account_id,
            identity_id=identity_id,
            email=email,
            status=AccountStatus.UNVERIFIED,
            hashed_password=hashed_password,
            password_history=HashedPasswordHistory.initialize(),
            totp_secret=None,
            recovery_code_set=HashedRecoveryCodeSet.initialize(),
            is_mfa_enabled=False,
            lockout_state=LockoutState.initialize(),
        )
        account.record_event(AccountRegistered(occurred_at=now, account_id=account_id))
        account.record_event(
            EmailVerificationRequested(occurred_at=now, account_id=account_id)
        )
        return account

    # --- Queries ---

    @property
    def identity_id(self) -> IdentityId:
        return self._identity_id

    @property
    def email(self) -> EmailAddress:
        return self._email

    @property
    def status(self) -> AccountStatus:
        return self._status

    @property
    def hashed_password(self) -> HashedPassword:
        return self._hashed_password

    @property
    def password_history(self) -> HashedPasswordHistory:
        return self._password_history

    @property
    def totp_secret(self) -> EncryptedTOTPSecret | None:
        return self._totp_secret

    @property
    def recovery_code_set(self) -> HashedRecoveryCodeSet:
        return self._recovery_code_set

    @property
    def is_mfa_enabled(self) -> bool:
        return self._is_mfa_enabled

    @property
    def lockout_state(self) -> LockoutState:
        return self._lockout_state

    # --- Email verification ---

    def verify_email(self, now: datetime) -> None:
        self._status.guard_is_unverified()
        self._mark_active()
        self.record_event(EmailVerified(occurred_at=now, account_id=self._id))

    def _mark_active(self) -> None:
        self._status = AccountStatus.ACTIVE

    # --- Account lifecycle ---

    def lock(self, now: datetime) -> None:
        self._status.guard_is_active()
        self._mark_locked()
        self._set_admin_lockout()
        self.record_event(
            AccountLocked(occurred_at=now, account_id=self._id, reason=LockReason.ADMIN)
        )

    def _mark_locked(self) -> None:
        self._status = AccountStatus.LOCKED

    def _set_admin_lockout(self) -> None:
        self._lockout_state = self._lockout_state.apply_indefinite_lockout()

    def unlock(self, now: datetime) -> None:
        self._status.guard_is_locked()
        self._mark_active()
        self._reset_lockout()
        self.record_event(
            AccountUnlocked(
                occurred_at=now, account_id=self._id, reason=UnlockReason.ADMIN
            )
        )

    def _reset_lockout(self) -> None:
        self._lockout_state = self._lockout_state.reset()

    def suspend(self, now: datetime) -> None:
        self._status.guard_not_unverified()
        self._status.guard_not_suspended()
        self._status.guard_not_closed()
        self._mark_suspended()
        self.record_event(AccountSuspended(occurred_at=now, account_id=self._id))

    def _mark_suspended(self) -> None:
        self._status = AccountStatus.SUSPENDED

    def close(self, now: datetime) -> None:
        self._status.guard_not_closed()
        self._mark_closed()
        self.record_event(AccountClosed(occurred_at=now, account_id=self._id))

    def _mark_closed(self) -> None:
        self._status = AccountStatus.CLOSED

    # --- Password management ---

    def change_password(
        self,
        new_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ) -> None:
        self._status.guard_is_active()
        self._rotate_password_history(password_policy.history_depth)
        self._set_password(new_password)
        self.record_event(PasswordChanged(occurred_at=now, account_id=self._id))

    def _rotate_password_history(self, depth: int) -> None:
        self._password_history = self._password_history.rotate(
            self._hashed_password, depth
        )

    def _set_password(self, hashed_password: HashedPassword) -> None:
        self._hashed_password = hashed_password

    def reset_password(
        self,
        new_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ) -> None:
        self._status.guard_is_active()
        self._rotate_password_history(password_policy.history_depth)
        self._set_password(new_password)
        self.record_event(PasswordResetCompleted(occurred_at=now, account_id=self._id))

    # --- TOTP management ---

    def add_totp_secret(
        self, encrypted_secret: EncryptedTOTPSecret, now: datetime
    ) -> None:
        self._status.guard_is_active()
        self._guard_no_existing_totp()
        self._set_totp_secret(encrypted_secret)
        self.record_event(TOTPSecretAdded(occurred_at=now, account_id=self._id))

    def _guard_no_existing_totp(self) -> None:
        if self._totp_secret is not None:
            raise DuplicateTOTPSecretError()

    def _set_totp_secret(self, encrypted_secret: EncryptedTOTPSecret) -> None:
        self._totp_secret = encrypted_secret

    def remove_totp_secret(self, now: datetime) -> None:
        self._status.guard_is_active()
        self._guard_totp_exists()
        self._guard_can_remove_totp()
        self._clear_totp_secret()
        self.record_event(TOTPSecretRemoved(occurred_at=now, account_id=self._id))

    def _guard_totp_exists(self) -> None:
        if self._totp_secret is None:
            raise TOTPSecretNotFoundError()

    def _guard_can_remove_totp(self) -> None:
        if self._is_mfa_enabled and not self._recovery_code_set.has_unused:
            raise CannotRemoveCredentialError()

    @property
    def _has_totp(self) -> bool:
        return self._totp_secret is not None

    def _clear_totp_secret(self) -> None:
        self._totp_secret = None

    # --- Recovery codes ---

    def add_recovery_codes(
        self, code_set: HashedRecoveryCodeSet, now: datetime
    ) -> None:
        self._status.guard_is_active()
        self._replace_recovery_codes(code_set)
        self.record_event(RecoveryCodesGenerated(occurred_at=now, account_id=self._id))

    def _replace_recovery_codes(self, code_set: HashedRecoveryCodeSet) -> None:
        self._recovery_code_set = code_set

    def consume_recovery_code(
        self, consumed_code: HashedRecoveryCode, now: datetime
    ) -> None:
        self._status.guard_is_active()
        self._consume_code(consumed_code, now)
        self.record_event(RecoveryCodeConsumed(occurred_at=now, account_id=self._id))

    def _consume_code(self, consumed_code: HashedRecoveryCode, now: datetime) -> None:
        self._recovery_code_set = self._recovery_code_set.with_code_consumed(
            consumed_code, now
        )

    # --- MFA management ---

    def enable_mfa(self, now: datetime) -> None:
        self._status.guard_is_active()
        self._guard_mfa_not_already_enabled()
        self._guard_has_totp_or_recovery_codes()
        self._mark_mfa_enabled()
        self.record_event(MFAEnabled(occurred_at=now, account_id=self._id))

    def _guard_mfa_not_already_enabled(self) -> None:
        if self._is_mfa_enabled:
            raise MFAAlreadyEnabledError()

    def _guard_has_totp_or_recovery_codes(self) -> None:
        if not self._has_totp and not self._recovery_code_set.has_unused:
            raise MFARequiresCredentialError()

    def _mark_mfa_enabled(self) -> None:
        self._is_mfa_enabled = True

    def disable_mfa(self, now: datetime) -> None:
        self._status.guard_is_active()
        self._guard_mfa_is_enabled()
        self._mark_mfa_disabled()
        self.record_event(MFADisabled(occurred_at=now, account_id=self._id))

    def _guard_mfa_is_enabled(self) -> None:
        if not self._is_mfa_enabled:
            raise MFANotEnabledError()

    def _mark_mfa_disabled(self) -> None:
        self._is_mfa_enabled = False

    # --- Lockout management ---

    def record_failed_attempt(
        self, now: datetime, lockout_policy: LockoutPolicy
    ) -> None:
        self._auto_unlock_if_expired(now)
        self._status.guard_is_active()
        self._increment_failed_attempts(now)
        self._lock_if_threshold_reached(now, lockout_policy)

    def _auto_unlock_if_expired(self, now: datetime) -> None:
        if not self._status.is_locked:
            return
        if not self._lockout_state.is_expired_timed_lockout(now):
            return
        self._mark_active()
        self._clear_lockout_expiry()
        self.record_event(
            AccountUnlocked(
                occurred_at=now, account_id=self._id, reason=UnlockReason.EXPIRY
            )
        )

    def _clear_lockout_expiry(self) -> None:
        self._lockout_state = self._lockout_state.clear_expiry()

    def _increment_failed_attempts(self, now: datetime) -> None:
        self._lockout_state = self._lockout_state.increment(now)

    def _lock_if_threshold_reached(
        self, now: datetime, lockout_policy: LockoutPolicy
    ) -> None:
        if not self._lockout_state.is_threshold_reached(lockout_policy.threshold):
            return
        self._apply_tiered_lockout(now, lockout_policy)
        self._mark_locked()
        self.record_event(
            AccountLocked(
                occurred_at=now, account_id=self._id, reason=LockReason.THRESHOLD
            )
        )

    def _apply_tiered_lockout(
        self, now: datetime, lockout_policy: LockoutPolicy
    ) -> None:
        self._lockout_state = self._lockout_state.apply_lockout(
            lockout_policy.tier_minutes, now
        )

    def record_successful_attempt(self, now: datetime) -> None:
        self._auto_unlock_if_expired(now)
        self._status.guard_is_active()
        self._reset_lockout()

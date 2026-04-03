from datetime import datetime, timedelta

import pytest

from pydentity.authentication.domain.account.aggregate import Account
from pydentity.authentication.domain.account.errors import (
    AccountAlreadyClosedError,
    AccountAlreadySuspendedError,
    AccountNotActiveError,
    AccountNotLockedError,
    AccountNotUnverifiedError,
    AccountUnverifiedError,
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
    HashedRecoveryCode,
    HashedRecoveryCodeSet,
    LockoutPolicy,
    LockReason,
    PasswordPolicy,
    UnlockReason,
)
from pydentity.shared_kernel import AccountId, IdentityId

# --- Factory ---


class TestAccountRegister:
    def test_creates_unverified_account(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        valid_email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ):
        account = Account.register(
            account_id, identity_id, valid_email, hashed_password, now
        )
        assert account.status == AccountStatus.UNVERIFIED

    def test_records_account_registered_event(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        valid_email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ):
        account = Account.register(
            account_id, identity_id, valid_email, hashed_password, now
        )
        assert isinstance(account.events[0], AccountRegistered)

    def test_records_email_verification_requested_event(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        valid_email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ):
        account = Account.register(
            account_id, identity_id, valid_email, hashed_password, now
        )
        assert isinstance(account.events[1], EmailVerificationRequested)

    def test_initializes_empty_password_history(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        valid_email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ):
        account = Account.register(
            account_id, identity_id, valid_email, hashed_password, now
        )
        assert account.password_history.hashes == ()

    def test_initializes_mfa_disabled(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        valid_email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ):
        account = Account.register(
            account_id, identity_id, valid_email, hashed_password, now
        )
        assert account.is_mfa_enabled is False

    def test_initializes_no_totp_secret(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        valid_email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ):
        account = Account.register(
            account_id, identity_id, valid_email, hashed_password, now
        )
        assert account.totp_secret is None

    def test_initializes_empty_recovery_codes(
        self,
        account_id: AccountId,
        identity_id: IdentityId,
        valid_email: EmailAddress,
        hashed_password: HashedPassword,
        now: datetime,
    ):
        account = Account.register(
            account_id, identity_id, valid_email, hashed_password, now
        )
        assert account.recovery_code_set.is_empty is True


# --- Email verification ---


class TestVerifyEmail:
    def test_transitions_to_active(self, registered_account: Account, now: datetime):
        registered_account.verify_email(now)
        assert registered_account.status == AccountStatus.ACTIVE

    def test_records_email_verified_event(
        self, registered_account: Account, now: datetime
    ):
        registered_account.verify_email(now)
        assert isinstance(registered_account.events[0], EmailVerified)

    def test_raises_when_not_unverified(self, active_account: Account, now: datetime):
        with pytest.raises(AccountNotUnverifiedError):
            active_account.verify_email(now)


# --- Lock ---


class TestLock:
    def test_transitions_to_locked(self, active_account: Account, now: datetime):
        active_account.lock(now)
        assert active_account.status == AccountStatus.LOCKED

    def test_records_account_locked_event_with_admin_reason(
        self, active_account: Account, now: datetime
    ):
        active_account.lock(now)
        event = active_account.events[0]
        assert isinstance(event, AccountLocked)
        assert event.reason == LockReason.ADMIN

    def test_applies_indefinite_lockout(self, active_account: Account, now: datetime):
        active_account.lock(now)
        assert active_account.lockout_state.lockout_until is None

    def test_raises_when_not_active(self, registered_account: Account, now: datetime):
        with pytest.raises(AccountNotActiveError):
            registered_account.lock(now)


# --- Unlock ---


class TestUnlock:
    def test_transitions_to_active(self, locked_account: Account, now: datetime):
        locked_account.unlock(now)
        assert locked_account.status == AccountStatus.ACTIVE

    def test_records_account_unlocked_event_with_admin_reason(
        self, locked_account: Account, now: datetime
    ):
        locked_account.unlock(now)
        event = locked_account.events[0]
        assert isinstance(event, AccountUnlocked)
        assert event.reason == UnlockReason.ADMIN

    def test_resets_lockout_state(self, locked_account: Account, now: datetime):
        locked_account.unlock(now)
        assert locked_account.lockout_state.failed_attempt_count == 0
        assert locked_account.lockout_state.lockout_count == 0

    def test_raises_when_not_locked(self, active_account: Account, now: datetime):
        with pytest.raises(AccountNotLockedError):
            active_account.unlock(now)


# --- Suspend ---


class TestSuspend:
    def test_transitions_to_suspended(self, active_account: Account, now: datetime):
        active_account.suspend(now)
        assert active_account.status == AccountStatus.SUSPENDED

    def test_records_account_suspended_event(
        self, active_account: Account, now: datetime
    ):
        active_account.suspend(now)
        assert isinstance(active_account.events[0], AccountSuspended)

    def test_raises_when_unverified(self, registered_account: Account, now: datetime):
        with pytest.raises(AccountUnverifiedError):
            registered_account.suspend(now)

    def test_raises_when_already_suspended(
        self, suspended_account: Account, now: datetime
    ):
        with pytest.raises(AccountAlreadySuspendedError):
            suspended_account.suspend(now)

    def test_raises_when_closed(self, closed_account: Account, now: datetime):
        with pytest.raises(AccountAlreadyClosedError):
            closed_account.suspend(now)


# --- Close ---


class TestClose:
    def test_transitions_to_closed(self, active_account: Account, now: datetime):
        active_account.close(now)
        assert active_account.status == AccountStatus.CLOSED

    def test_records_account_closed_event(self, active_account: Account, now: datetime):
        active_account.close(now)
        assert isinstance(active_account.events[0], AccountClosed)

    def test_raises_when_already_closed(self, closed_account: Account, now: datetime):
        with pytest.raises(AccountAlreadyClosedError):
            closed_account.close(now)

    def test_succeeds_from_locked(self, locked_account: Account, now: datetime):
        locked_account.close(now)
        assert locked_account.status == AccountStatus.CLOSED

    def test_succeeds_from_suspended(self, suspended_account: Account, now: datetime):
        suspended_account.close(now)
        assert suspended_account.status == AccountStatus.CLOSED


# --- Change password ---


class TestChangePassword:
    def test_updates_password(
        self,
        active_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        active_account.change_password(another_hashed_password, password_policy, now)
        assert active_account.hashed_password == another_hashed_password

    def test_rotates_history(
        self,
        active_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        old_password = active_account.hashed_password
        active_account.change_password(another_hashed_password, password_policy, now)
        assert old_password in active_account.password_history.hashes

    def test_records_password_changed_event(
        self,
        active_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        active_account.change_password(another_hashed_password, password_policy, now)
        assert isinstance(active_account.events[0], PasswordChanged)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.change_password(
                another_hashed_password, password_policy, now
            )


# --- Reset password ---


class TestResetPassword:
    def test_updates_password(
        self,
        active_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        active_account.reset_password(another_hashed_password, password_policy, now)
        assert active_account.hashed_password == another_hashed_password

    def test_rotates_history(
        self,
        active_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        old_password = active_account.hashed_password
        active_account.reset_password(another_hashed_password, password_policy, now)
        assert old_password in active_account.password_history.hashes

    def test_records_password_reset_completed_event(
        self,
        active_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        active_account.reset_password(another_hashed_password, password_policy, now)
        assert isinstance(active_account.events[0], PasswordResetCompleted)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        another_hashed_password: HashedPassword,
        password_policy: PasswordPolicy,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.reset_password(another_hashed_password, password_policy, now)


# --- TOTP management ---


class TestAddTOTPSecret:
    def test_stores_secret(
        self,
        active_account: Account,
        totp_secret: EncryptedTOTPSecret,
        now: datetime,
    ):
        active_account.add_totp_secret(totp_secret, now)
        assert active_account.totp_secret == totp_secret

    def test_records_totp_secret_added_event(
        self,
        active_account: Account,
        totp_secret: EncryptedTOTPSecret,
        now: datetime,
    ):
        active_account.add_totp_secret(totp_secret, now)
        assert isinstance(active_account.events[0], TOTPSecretAdded)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        totp_secret: EncryptedTOTPSecret,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.add_totp_secret(totp_secret, now)

    def test_raises_when_already_exists(
        self,
        active_account_with_totp: Account,
        now: datetime,
    ):
        new_secret = EncryptedTOTPSecret(value=b"another_secret")
        with pytest.raises(DuplicateTOTPSecretError):
            active_account_with_totp.add_totp_secret(new_secret, now)


class TestRemoveTOTPSecret:
    def test_clears_secret(
        self,
        active_account_with_totp: Account,
        now: datetime,
    ):
        active_account_with_totp.remove_totp_secret(now)
        assert active_account_with_totp.totp_secret is None

    def test_records_totp_secret_removed_event(
        self,
        active_account_with_totp: Account,
        now: datetime,
    ):
        active_account_with_totp.remove_totp_secret(now)
        assert isinstance(active_account_with_totp.events[0], TOTPSecretRemoved)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.remove_totp_secret(now)

    def test_raises_when_no_totp(
        self,
        active_account: Account,
        now: datetime,
    ):
        with pytest.raises(TOTPSecretNotFoundError):
            active_account.remove_totp_secret(now)

    def test_raises_when_mfa_enabled_and_no_unused_recovery_codes(
        self,
        active_account_with_mfa: Account,
        now: datetime,
    ):
        used_at = now
        used_code = HashedRecoveryCode(
            value="$argon2id$recovery_code_1", used_at=used_at
        )
        all_used_set = HashedRecoveryCodeSet(codes=(used_code,))
        active_account_with_mfa.add_recovery_codes(all_used_set, now)
        active_account_with_mfa.clear_events()
        with pytest.raises(CannotRemoveCredentialError):
            active_account_with_mfa.remove_totp_secret(now)


# --- Recovery codes ---


class TestAddRecoveryCodes:
    def test_replaces_code_set(
        self,
        active_account: Account,
        recovery_code_set: HashedRecoveryCodeSet,
        now: datetime,
    ):
        active_account.add_recovery_codes(recovery_code_set, now)
        assert active_account.recovery_code_set == recovery_code_set

    def test_records_recovery_codes_generated_event(
        self,
        active_account: Account,
        recovery_code_set: HashedRecoveryCodeSet,
        now: datetime,
    ):
        active_account.add_recovery_codes(recovery_code_set, now)
        assert isinstance(active_account.events[0], RecoveryCodesGenerated)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        recovery_code_set: HashedRecoveryCodeSet,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.add_recovery_codes(recovery_code_set, now)


class TestConsumeRecoveryCode:
    def test_marks_code_used(
        self,
        active_account: Account,
        unused_recovery_code: HashedRecoveryCode,
        recovery_code_set: HashedRecoveryCodeSet,
        now: datetime,
    ):
        active_account.add_recovery_codes(recovery_code_set, now)
        active_account.clear_events()
        active_account.consume_recovery_code(unused_recovery_code, now)
        assert active_account.recovery_code_set.codes[0].used_at == now

    def test_records_recovery_code_consumed_event(
        self,
        active_account: Account,
        unused_recovery_code: HashedRecoveryCode,
        recovery_code_set: HashedRecoveryCodeSet,
        now: datetime,
    ):
        active_account.add_recovery_codes(recovery_code_set, now)
        active_account.clear_events()
        active_account.consume_recovery_code(unused_recovery_code, now)
        assert isinstance(active_account.events[0], RecoveryCodeConsumed)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        unused_recovery_code: HashedRecoveryCode,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.consume_recovery_code(unused_recovery_code, now)


# --- MFA management ---


class TestEnableMFA:
    def test_with_totp_sets_flag(
        self,
        active_account_with_totp: Account,
        recovery_code_set: HashedRecoveryCodeSet,
        now: datetime,
    ):
        active_account_with_totp.add_recovery_codes(recovery_code_set, now)
        active_account_with_totp.clear_events()
        active_account_with_totp.enable_mfa(now)
        assert active_account_with_totp.is_mfa_enabled is True

    def test_records_mfa_enabled_event(
        self,
        active_account_with_totp: Account,
        recovery_code_set: HashedRecoveryCodeSet,
        now: datetime,
    ):
        active_account_with_totp.add_recovery_codes(recovery_code_set, now)
        active_account_with_totp.clear_events()
        active_account_with_totp.enable_mfa(now)
        assert isinstance(active_account_with_totp.events[0], MFAEnabled)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.enable_mfa(now)

    def test_raises_when_already_enabled(
        self,
        active_account_with_mfa: Account,
        now: datetime,
    ):
        with pytest.raises(MFAAlreadyEnabledError):
            active_account_with_mfa.enable_mfa(now)

    def test_raises_when_no_credentials(
        self,
        active_account: Account,
        now: datetime,
    ):
        with pytest.raises(MFARequiresCredentialError):
            active_account.enable_mfa(now)


class TestDisableMFA:
    def test_clears_flag(
        self,
        active_account_with_mfa: Account,
        now: datetime,
    ):
        active_account_with_mfa.disable_mfa(now)
        assert active_account_with_mfa.is_mfa_enabled is False

    def test_records_mfa_disabled_event(
        self,
        active_account_with_mfa: Account,
        now: datetime,
    ):
        active_account_with_mfa.disable_mfa(now)
        assert isinstance(active_account_with_mfa.events[0], MFADisabled)

    def test_raises_when_not_active(
        self,
        locked_account: Account,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.disable_mfa(now)

    def test_raises_when_not_enabled(
        self,
        active_account: Account,
        now: datetime,
    ):
        with pytest.raises(MFANotEnabledError):
            active_account.disable_mfa(now)


# --- Lockout management ---


class TestRecordFailedAttempt:
    def test_increments_lockout_count(
        self,
        active_account: Account,
        lockout_policy: LockoutPolicy,
        now: datetime,
    ):
        active_account.record_failed_attempt(now, lockout_policy)
        assert active_account.lockout_state.failed_attempt_count == 1

    def test_locks_at_threshold(
        self,
        active_account: Account,
        now: datetime,
    ):
        policy = LockoutPolicy(threshold=3, tier_minutes=(5,))
        for i in range(3):
            active_account.record_failed_attempt(now + timedelta(seconds=i), policy)
        assert active_account.status == AccountStatus.LOCKED

    def test_records_account_locked_event_at_threshold(
        self,
        active_account: Account,
        now: datetime,
    ):
        policy = LockoutPolicy(threshold=2, tier_minutes=(5,))
        active_account.record_failed_attempt(now, policy)
        active_account.clear_events()
        active_account.record_failed_attempt(now + timedelta(seconds=1), policy)
        locked_events = [
            e for e in active_account.events if isinstance(e, AccountLocked)
        ]
        assert len(locked_events) == 1
        assert locked_events[0].reason == LockReason.THRESHOLD

    def test_auto_unlocks_expired_lockout(
        self,
        active_account: Account,
        now: datetime,
    ):
        policy = LockoutPolicy(threshold=2, tier_minutes=(5,))
        active_account.record_failed_attempt(now, policy)
        active_account.record_failed_attempt(now + timedelta(seconds=1), policy)
        assert active_account.status == AccountStatus.LOCKED
        active_account.clear_events()
        after_expiry = now + timedelta(minutes=10)
        active_account.record_failed_attempt(after_expiry, policy)
        unlock_events = [
            e for e in active_account.events if isinstance(e, AccountUnlocked)
        ]
        assert len(unlock_events) == 1
        assert unlock_events[0].reason == UnlockReason.EXPIRY

    def test_raises_when_not_active_and_not_expired(
        self,
        locked_account: Account,
        lockout_policy: LockoutPolicy,
        now: datetime,
    ):
        with pytest.raises(AccountNotActiveError):
            locked_account.record_failed_attempt(now, lockout_policy)


class TestRecordSuccessfulAttempt:
    def test_resets_lockout(
        self,
        active_account: Account,
        lockout_policy: LockoutPolicy,
        now: datetime,
    ):
        active_account.record_failed_attempt(now, lockout_policy)
        active_account.record_successful_attempt(now + timedelta(seconds=1))
        assert active_account.lockout_state.failed_attempt_count == 0

    def test_auto_unlocks_expired_lockout(
        self,
        active_account: Account,
        now: datetime,
    ):
        policy = LockoutPolicy(threshold=2, tier_minutes=(5,))
        active_account.record_failed_attempt(now, policy)
        active_account.record_failed_attempt(now + timedelta(seconds=1), policy)
        assert active_account.status == AccountStatus.LOCKED
        after_expiry = now + timedelta(minutes=10)
        active_account.record_successful_attempt(after_expiry)
        assert active_account.status == AccountStatus.ACTIVE

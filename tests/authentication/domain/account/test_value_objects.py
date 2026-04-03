from datetime import UTC, datetime, timedelta

import pytest

from pydentity.authentication.domain.account.errors import (
    AccountAlreadyClosedError,
    AccountAlreadySuspendedError,
    AccountNotActiveError,
    AccountNotLockedError,
    AccountNotUnverifiedError,
    AccountUnverifiedError,
    PasswordPolicyViolationError,
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

# --- AccountStatus ---


class TestAccountStatus:
    def test_unverified_query(self):
        assert AccountStatus.UNVERIFIED.is_unverified is True
        assert AccountStatus.UNVERIFIED.is_active is False

    def test_active_query(self):
        assert AccountStatus.ACTIVE.is_active is True
        assert AccountStatus.ACTIVE.is_unverified is False

    def test_locked_query(self):
        assert AccountStatus.LOCKED.is_locked is True
        assert AccountStatus.LOCKED.is_active is False

    def test_suspended_query(self):
        assert AccountStatus.SUSPENDED.is_suspended is True

    def test_closed_query(self):
        assert AccountStatus.CLOSED.is_closed is True

    def test_guard_is_unverified_passes(self):
        AccountStatus.UNVERIFIED.guard_is_unverified()

    def test_guard_is_unverified_raises_when_active(self):
        with pytest.raises(AccountNotUnverifiedError):
            AccountStatus.ACTIVE.guard_is_unverified()

    def test_guard_is_active_passes(self):
        AccountStatus.ACTIVE.guard_is_active()

    def test_guard_is_active_raises_when_locked(self):
        with pytest.raises(AccountNotActiveError):
            AccountStatus.LOCKED.guard_is_active()

    def test_guard_is_locked_passes(self):
        AccountStatus.LOCKED.guard_is_locked()

    def test_guard_is_locked_raises_when_active(self):
        with pytest.raises(AccountNotLockedError):
            AccountStatus.ACTIVE.guard_is_locked()

    def test_guard_not_unverified_passes_when_active(self):
        AccountStatus.ACTIVE.guard_not_unverified()

    def test_guard_not_unverified_raises_when_unverified(self):
        with pytest.raises(AccountUnverifiedError):
            AccountStatus.UNVERIFIED.guard_not_unverified()

    def test_guard_not_suspended_passes_when_active(self):
        AccountStatus.ACTIVE.guard_not_suspended()

    def test_guard_not_suspended_raises_when_suspended(self):
        with pytest.raises(AccountAlreadySuspendedError):
            AccountStatus.SUSPENDED.guard_not_suspended()

    def test_guard_not_closed_passes_when_active(self):
        AccountStatus.ACTIVE.guard_not_closed()

    def test_guard_not_closed_raises_when_closed(self):
        with pytest.raises(AccountAlreadyClosedError):
            AccountStatus.CLOSED.guard_not_closed()


# --- LockReason / UnlockReason ---


class TestLockReason:
    def test_values(self):
        assert LockReason.ADMIN == "admin"
        assert LockReason.THRESHOLD == "threshold"


class TestUnlockReason:
    def test_values(self):
        assert UnlockReason.ADMIN == "admin"
        assert UnlockReason.EXPIRY == "expiry"


# --- EmailAddress ---


class TestEmailAddress:
    def test_valid_creation(self):
        email = EmailAddress(value="user@example.com")
        assert email.value == "user@example.com"

    def test_normalizes_to_lowercase(self):
        email = EmailAddress(value="User@EXAMPLE.com")
        assert email.value == "user@example.com"

    def test_strips_whitespace(self):
        email = EmailAddress(value="  user@example.com  ")
        assert email.value == "user@example.com"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            EmailAddress(value="")

    def test_rejects_exceeding_max_length(self):
        local = "a" * 64
        domain = "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + ".com"
        long_email = f"{local}@{domain}"
        if len(long_email) <= 254:
            EmailAddress(value=long_email)
        with pytest.raises(ValueError):
            EmailAddress(value="a" * 65 + "@" + "b" * 190 + ".com")

    def test_rejects_no_at_sign(self):
        with pytest.raises(ValueError):
            EmailAddress(value="userexample.com")

    def test_rejects_multiple_at_signs(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@@example.com")

    def test_rejects_empty_local_part(self):
        with pytest.raises(ValueError):
            EmailAddress(value="@example.com")

    def test_rejects_local_part_exceeding_max_length(self):
        with pytest.raises(ValueError):
            EmailAddress(value="a" * 65 + "@example.com")

    def test_rejects_leading_dot_in_local_part(self):
        with pytest.raises(ValueError):
            EmailAddress(value=".user@example.com")

    def test_rejects_trailing_dot_in_local_part(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user.@example.com")

    def test_rejects_consecutive_dots_in_local_part(self):
        with pytest.raises(ValueError):
            EmailAddress(value="us..er@example.com")

    def test_rejects_empty_domain(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@")

    def test_rejects_domain_without_dot(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@localhost")

    def test_rejects_empty_domain_label(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@.example.com")

    def test_rejects_domain_label_exceeding_max_length(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@" + "a" * 64 + ".com")

    def test_rejects_domain_label_leading_hyphen(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@-example.com")

    def test_rejects_domain_label_trailing_hyphen(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@example-.com")

    def test_rejects_domain_label_with_special_characters(self):
        with pytest.raises(ValueError):
            EmailAddress(value="user@exam!ple.com")


# --- HashedPassword ---


class TestHashedPassword:
    def test_valid_creation(self):
        password = HashedPassword(value="$argon2id$hash")
        assert password.value == "$argon2id$hash"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            HashedPassword(value="")

    def test_rejects_exceeding_max_length(self):
        with pytest.raises(ValueError):
            HashedPassword(value="x" * 257)


# --- HashedPasswordHistory ---


class TestHashedPasswordHistory:
    def test_initialize_empty(self):
        history = HashedPasswordHistory.initialize()
        assert history.hashes == ()

    def test_prepend(self):
        password = HashedPassword(value="$hash1")
        history = HashedPasswordHistory.initialize().prepend(password)
        assert history.hashes == (password,)

    def test_truncate(self):
        password_1 = HashedPassword(value="$hash1")
        password_2 = HashedPassword(value="$hash2")
        password_3 = HashedPassword(value="$hash3")
        history = HashedPasswordHistory(hashes=(password_1, password_2, password_3))
        truncated = history.truncate(2)
        assert truncated.hashes == (password_1, password_2)

    def test_rotate_prepends_then_truncates(self):
        old_password = HashedPassword(value="$old")
        current_password = HashedPassword(value="$current")
        history = HashedPasswordHistory(hashes=(old_password,))
        rotated = history.rotate(current_password, depth=2)
        assert rotated.hashes == (current_password, old_password)

    def test_rotate_truncates_to_depth(self):
        password_1 = HashedPassword(value="$hash1")
        password_2 = HashedPassword(value="$hash2")
        current = HashedPassword(value="$current")
        history = HashedPasswordHistory(hashes=(password_1, password_2))
        rotated = history.rotate(current, depth=2)
        assert rotated.hashes == (current, password_1)

    def test_rejects_exceeding_max_size(self):
        passwords = tuple(HashedPassword(value=f"$hash{i}") for i in range(25))
        with pytest.raises(ValueError):
            HashedPasswordHistory(hashes=passwords)


# --- EncryptedTOTPSecret ---


class TestEncryptedTOTPSecret:
    def test_valid_creation(self):
        secret = EncryptedTOTPSecret(value=b"encrypted_bytes")
        assert secret.value == b"encrypted_bytes"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            EncryptedTOTPSecret(value=b"")

    def test_rejects_exceeding_max_size(self):
        with pytest.raises(ValueError):
            EncryptedTOTPSecret(value=b"x" * 513)


# --- HashedRecoveryCode ---


class TestHashedRecoveryCode:
    def test_valid_creation(self):
        code = HashedRecoveryCode(value="$hash", used_at=None)
        assert code.value == "$hash"

    def test_is_unused_when_used_at_is_none(self):
        code = HashedRecoveryCode(value="$hash", used_at=None)
        assert code.is_unused is True

    def test_is_not_unused_when_marked_used(self):
        used_at = datetime(2026, 1, 1, tzinfo=UTC)
        code = HashedRecoveryCode(value="$hash", used_at=used_at)
        assert code.is_unused is False

    def test_mark_used_returns_new_instance(self):
        code = HashedRecoveryCode(value="$hash", used_at=None)
        used_at = datetime(2026, 1, 1, tzinfo=UTC)
        marked = code.mark_used(used_at)
        assert marked.used_at == used_at
        assert marked.value == "$hash"
        assert code.used_at is None

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            HashedRecoveryCode(value="", used_at=None)

    def test_rejects_exceeding_max_length(self):
        with pytest.raises(ValueError):
            HashedRecoveryCode(value="x" * 257, used_at=None)


# --- HashedRecoveryCodeSet ---


class TestHashedRecoveryCodeSet:
    def test_initialize_empty(self):
        code_set = HashedRecoveryCodeSet.initialize()
        assert code_set.codes == ()

    def test_is_empty_when_no_codes(self):
        code_set = HashedRecoveryCodeSet.initialize()
        assert code_set.is_empty is True

    def test_is_not_empty_when_has_codes(self):
        code = HashedRecoveryCode(value="$hash", used_at=None)
        code_set = HashedRecoveryCodeSet(codes=(code,))
        assert code_set.is_empty is False

    def test_has_unused_when_unused_codes_exist(self):
        code = HashedRecoveryCode(value="$hash", used_at=None)
        code_set = HashedRecoveryCodeSet(codes=(code,))
        assert code_set.has_unused is True

    def test_has_no_unused_when_all_consumed(self):
        used_at = datetime(2026, 1, 1, tzinfo=UTC)
        code = HashedRecoveryCode(value="$hash", used_at=used_at)
        code_set = HashedRecoveryCodeSet(codes=(code,))
        assert code_set.has_unused is False

    def test_with_code_consumed(self):
        code = HashedRecoveryCode(value="$hash", used_at=None)
        code_set = HashedRecoveryCodeSet(codes=(code,))
        consumed_at = datetime(2026, 1, 1, tzinfo=UTC)
        updated = code_set.with_code_consumed(code, consumed_at)
        assert updated.codes[0].used_at == consumed_at

    def test_with_code_consumed_only_marks_matching_code(self):
        code_1 = HashedRecoveryCode(value="$hash1", used_at=None)
        code_2 = HashedRecoveryCode(value="$hash2", used_at=None)
        code_set = HashedRecoveryCodeSet(codes=(code_1, code_2))
        consumed_at = datetime(2026, 1, 1, tzinfo=UTC)
        updated = code_set.with_code_consumed(code_1, consumed_at)
        assert updated.codes[0].used_at == consumed_at
        assert updated.codes[1].used_at is None

    def test_rejects_exceeding_max_size(self):
        codes = tuple(
            HashedRecoveryCode(value=f"$hash{i}", used_at=None) for i in range(21)
        )
        with pytest.raises(ValueError):
            HashedRecoveryCodeSet(codes=codes)


# --- LockoutState ---


class TestLockoutState:
    def test_initialize_all_zeros(self):
        state = LockoutState.initialize()
        assert state.failed_attempt_count == 0
        assert state.lockout_count == 0
        assert state.last_failed_at is None
        assert state.lockout_until is None

    def test_increment_adds_one_and_records_timestamp(self):
        state = LockoutState.initialize()
        now = datetime(2026, 1, 1, tzinfo=UTC)
        incremented = state.increment(now)
        assert incremented.failed_attempt_count == 1
        assert incremented.last_failed_at == now

    def test_is_threshold_reached_at_boundary(self):
        state = LockoutState(
            failed_attempt_count=5,
            lockout_count=0,
            last_failed_at=None,
            lockout_until=None,
        )
        assert state.is_threshold_reached(5) is True

    def test_is_threshold_not_reached_below(self):
        state = LockoutState(
            failed_attempt_count=4,
            lockout_count=0,
            last_failed_at=None,
            lockout_until=None,
        )
        assert state.is_threshold_reached(5) is False

    def test_apply_lockout_first_tier(self):
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        state = LockoutState(
            failed_attempt_count=5,
            lockout_count=0,
            last_failed_at=now,
            lockout_until=None,
        )
        locked = state.apply_lockout((5, 15, 60), now)
        assert locked.lockout_until == now + timedelta(minutes=5)
        assert locked.failed_attempt_count == 0
        assert locked.lockout_count == 1

    def test_apply_lockout_second_tier(self):
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        state = LockoutState(
            failed_attempt_count=5,
            lockout_count=1,
            last_failed_at=now,
            lockout_until=None,
        )
        locked = state.apply_lockout((5, 15, 60), now)
        assert locked.lockout_until == now + timedelta(minutes=15)
        assert locked.lockout_count == 2

    def test_apply_lockout_clamps_to_last_tier(self):
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        state = LockoutState(
            failed_attempt_count=5,
            lockout_count=10,
            last_failed_at=now,
            lockout_until=None,
        )
        locked = state.apply_lockout((5, 15, 60), now)
        assert locked.lockout_until == now + timedelta(minutes=60)

    def test_is_expired_timed_lockout_true(self):
        lockout_until = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        state = LockoutState(
            failed_attempt_count=0,
            lockout_count=1,
            last_failed_at=None,
            lockout_until=lockout_until,
        )
        after_expiry = lockout_until + timedelta(minutes=1)
        assert state.is_expired_timed_lockout(after_expiry) is True

    def test_is_expired_timed_lockout_false_when_not_expired(self):
        lockout_until = datetime(2026, 1, 1, 12, 30, 0, tzinfo=UTC)
        state = LockoutState(
            failed_attempt_count=0,
            lockout_count=1,
            last_failed_at=None,
            lockout_until=lockout_until,
        )
        before_expiry = lockout_until - timedelta(minutes=1)
        assert state.is_expired_timed_lockout(before_expiry) is False

    def test_is_expired_false_when_no_lockout_until(self):
        state = LockoutState.initialize()
        now = datetime(2026, 1, 1, tzinfo=UTC)
        assert state.is_expired(now) is False

    def test_is_timed_true_when_lockout_until_set(self):
        state = LockoutState(
            failed_attempt_count=0,
            lockout_count=1,
            last_failed_at=None,
            lockout_until=datetime(2026, 1, 1, tzinfo=UTC),
        )
        assert state.is_timed is True

    def test_is_timed_false_when_no_lockout_until(self):
        assert LockoutState.initialize().is_timed is False

    def test_reset_returns_initial(self):
        state = LockoutState(
            failed_attempt_count=5,
            lockout_count=3,
            last_failed_at=datetime(2026, 1, 1, tzinfo=UTC),
            lockout_until=datetime(2026, 1, 2, tzinfo=UTC),
        )
        reset = state.reset()
        assert reset == LockoutState.initialize()

    def test_clear_expiry_removes_lockout_until(self):
        state = LockoutState(
            failed_attempt_count=3,
            lockout_count=1,
            last_failed_at=datetime(2026, 1, 1, tzinfo=UTC),
            lockout_until=datetime(2026, 1, 2, tzinfo=UTC),
        )
        cleared = state.clear_expiry()
        assert cleared.lockout_until is None
        assert cleared.failed_attempt_count == 0

    def test_apply_indefinite_lockout_sets_no_expiry(self):
        state = LockoutState(
            failed_attempt_count=5,
            lockout_count=1,
            last_failed_at=datetime(2026, 1, 1, tzinfo=UTC),
            lockout_until=datetime(2026, 1, 2, tzinfo=UTC),
        )
        indefinite = state.apply_indefinite_lockout()
        assert indefinite.lockout_until is None
        assert indefinite.failed_attempt_count == 5

    def test_rejects_negative_failed_attempts(self):
        with pytest.raises(ValueError):
            LockoutState(
                failed_attempt_count=-1,
                lockout_count=0,
                last_failed_at=None,
                lockout_until=None,
            )

    def test_rejects_exceeding_max_failed_attempts(self):
        with pytest.raises(ValueError):
            LockoutState(
                failed_attempt_count=101,
                lockout_count=0,
                last_failed_at=None,
                lockout_until=None,
            )

    def test_rejects_negative_lockout_count(self):
        with pytest.raises(ValueError):
            LockoutState(
                failed_attempt_count=0,
                lockout_count=-1,
                last_failed_at=None,
                lockout_until=None,
            )


# --- LockoutPolicy ---


class TestLockoutPolicy:
    def test_valid_creation(self):
        policy = LockoutPolicy(threshold=5, tier_minutes=(5, 15, 60))
        assert policy.threshold == 5
        assert policy.tier_minutes == (5, 15, 60)

    def test_rejects_zero_threshold(self):
        with pytest.raises(ValueError):
            LockoutPolicy(threshold=0, tier_minutes=(5,))

    def test_rejects_exceeding_max_threshold(self):
        with pytest.raises(ValueError):
            LockoutPolicy(threshold=101, tier_minutes=(5,))

    def test_rejects_empty_tier_minutes(self):
        with pytest.raises(ValueError):
            LockoutPolicy(threshold=5, tier_minutes=())

    def test_rejects_non_positive_tier_minutes(self):
        with pytest.raises(ValueError):
            LockoutPolicy(threshold=5, tier_minutes=(0,))

    def test_rejects_tier_minutes_exceeding_max(self):
        with pytest.raises(ValueError):
            LockoutPolicy(threshold=5, tier_minutes=(1441,))


# --- PasswordPolicy ---


class TestPasswordPolicy:
    def test_valid_creation(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
            history_depth=5,
        )
        assert policy.min_length == 8

    def test_rejects_min_below_absolute_min(self):
        with pytest.raises(ValueError):
            PasswordPolicy(
                min_length=7,
                max_length=128,
                require_uppercase=False,
                require_lowercase=False,
                require_digit=False,
                require_special=False,
                history_depth=0,
            )

    def test_rejects_max_above_absolute_max(self):
        with pytest.raises(ValueError):
            PasswordPolicy(
                min_length=8,
                max_length=129,
                require_uppercase=False,
                require_lowercase=False,
                require_digit=False,
                require_special=False,
                history_depth=0,
            )

    def test_rejects_min_greater_than_max(self):
        with pytest.raises(ValueError):
            PasswordPolicy(
                min_length=20,
                max_length=10,
                require_uppercase=False,
                require_lowercase=False,
                require_digit=False,
                require_special=False,
                history_depth=0,
            )

    def test_rejects_negative_history_depth(self):
        with pytest.raises(ValueError):
            PasswordPolicy(
                min_length=8,
                max_length=128,
                require_uppercase=False,
                require_lowercase=False,
                require_digit=False,
                require_special=False,
                history_depth=-1,
            )

    def test_rejects_history_depth_exceeding_max(self):
        with pytest.raises(ValueError):
            PasswordPolicy(
                min_length=8,
                max_length=128,
                require_uppercase=False,
                require_lowercase=False,
                require_digit=False,
                require_special=False,
                history_depth=25,
            )

    def test_validate_passes_strong_password(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
            history_depth=0,
        )
        policy.validate("Str0ng!Pass")

    def test_validate_rejects_empty(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
            history_depth=0,
        )
        with pytest.raises(PasswordPolicyViolationError):
            policy.validate("")

    def test_validate_rejects_too_short(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
            history_depth=0,
        )
        with pytest.raises(PasswordPolicyViolationError):
            policy.validate("short")

    def test_validate_rejects_too_long(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=20,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
            history_depth=0,
        )
        with pytest.raises(PasswordPolicyViolationError):
            policy.validate("a" * 21)

    def test_validate_rejects_missing_uppercase(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=True,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
            history_depth=0,
        )
        with pytest.raises(PasswordPolicyViolationError):
            policy.validate("alllowercase1!")

    def test_validate_rejects_missing_lowercase(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=False,
            require_lowercase=True,
            require_digit=False,
            require_special=False,
            history_depth=0,
        )
        with pytest.raises(PasswordPolicyViolationError):
            policy.validate("ALLUPPERCASE1!")

    def test_validate_rejects_missing_digit(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=True,
            require_special=False,
            history_depth=0,
        )
        with pytest.raises(PasswordPolicyViolationError):
            policy.validate("NoDigitsHere!")

    def test_validate_rejects_missing_special(self):
        policy = PasswordPolicy(
            min_length=8,
            max_length=128,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=True,
            history_depth=0,
        )
        with pytest.raises(PasswordPolicyViolationError):
            policy.validate("NoSpecial123")

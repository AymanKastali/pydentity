from datetime import UTC, datetime, timedelta

import pytest

from pydentity.authentication.domain.recovery_request.errors import (
    RecoveryRequestAlreadyCompletedError,
    RecoveryRequestAlreadyExpiredError,
    RecoveryRequestNotPendingError,
    RecoveryRequestNotVerifiedError,
    RecoveryTokenExpiredError,
)
from pydentity.authentication.domain.recovery_request.value_objects import (
    RecoveryRequestStatus,
    RecoveryToken,
)

# --- RecoveryRequestStatus ---


class TestRecoveryRequestStatus:
    def test_pending_query(self):
        assert RecoveryRequestStatus.PENDING.is_pending is True

    def test_verified_query(self):
        assert RecoveryRequestStatus.VERIFIED.is_verified is True

    def test_completed_query(self):
        assert RecoveryRequestStatus.COMPLETED.is_completed is True

    def test_expired_query(self):
        assert RecoveryRequestStatus.EXPIRED.is_expired is True

    def test_guard_is_pending_passes(self):
        RecoveryRequestStatus.PENDING.guard_is_pending()

    def test_guard_is_pending_raises(self):
        with pytest.raises(RecoveryRequestNotPendingError):
            RecoveryRequestStatus.VERIFIED.guard_is_pending()

    def test_guard_is_verified_passes(self):
        RecoveryRequestStatus.VERIFIED.guard_is_verified()

    def test_guard_is_verified_raises(self):
        with pytest.raises(RecoveryRequestNotVerifiedError):
            RecoveryRequestStatus.PENDING.guard_is_verified()

    def test_guard_not_completed_passes(self):
        RecoveryRequestStatus.PENDING.guard_not_completed()

    def test_guard_not_completed_raises(self):
        with pytest.raises(RecoveryRequestAlreadyCompletedError):
            RecoveryRequestStatus.COMPLETED.guard_not_completed()

    def test_guard_not_expired_passes(self):
        RecoveryRequestStatus.PENDING.guard_not_expired()

    def test_guard_not_expired_raises(self):
        with pytest.raises(RecoveryRequestAlreadyExpiredError):
            RecoveryRequestStatus.EXPIRED.guard_not_expired()


# --- RecoveryToken ---


class TestRecoveryToken:
    def test_valid_creation(self):
        token = RecoveryToken(
            token_hash="$hash",
            expires_at=datetime(2026, 6, 1, tzinfo=UTC),
        )
        assert token.token_hash == "$hash"

    def test_rejects_empty_hash(self):
        with pytest.raises(ValueError):
            RecoveryToken(
                token_hash="",
                expires_at=datetime(2026, 6, 1, tzinfo=UTC),
            )

    def test_is_expired_true(self):
        expires_at = datetime(2026, 1, 1, tzinfo=UTC)
        token = RecoveryToken(token_hash="$h", expires_at=expires_at)
        after = expires_at + timedelta(minutes=1)
        assert token.is_expired(after) is True

    def test_guard_not_expired_passes(self):
        expires_at = datetime(2026, 6, 1, tzinfo=UTC)
        token = RecoveryToken(token_hash="$h", expires_at=expires_at)
        before = expires_at - timedelta(minutes=1)
        token.guard_not_expired(before)

    def test_guard_not_expired_raises(self):
        expires_at = datetime(2026, 1, 1, tzinfo=UTC)
        token = RecoveryToken(token_hash="$h", expires_at=expires_at)
        after = expires_at + timedelta(minutes=1)
        with pytest.raises(RecoveryTokenExpiredError):
            token.guard_not_expired(after)

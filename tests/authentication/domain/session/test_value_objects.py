from datetime import UTC, datetime, timedelta

import pytest

from pydentity.authentication.domain.session.errors import (
    RefreshTokenExpiredError,
    RefreshTokenRevokedError,
    SessionAlreadyEndedError,
)
from pydentity.authentication.domain.session.value_objects import (
    RefreshToken,
    SessionEndReason,
    SessionStatus,
)

# --- SessionStatus ---


class TestSessionStatus:
    def test_active_query(self):
        assert SessionStatus.ACTIVE.is_active is True
        assert SessionStatus.ACTIVE.is_ended is False

    def test_ended_query(self):
        assert SessionStatus.ENDED.is_ended is True
        assert SessionStatus.ENDED.is_active is False

    def test_guard_is_active_passes(self):
        SessionStatus.ACTIVE.guard_is_active()

    def test_guard_is_active_raises_when_ended(self):
        with pytest.raises(SessionAlreadyEndedError):
            SessionStatus.ENDED.guard_is_active()


# --- SessionEndReason ---


class TestSessionEndReason:
    def test_values(self):
        assert SessionEndReason.LOGOUT == "logout"
        assert SessionEndReason.IDLE_TIMEOUT == "idle_timeout"
        assert SessionEndReason.ABSOLUTE_TIMEOUT == "absolute_timeout"
        assert SessionEndReason.FORCED == "forced"
        assert SessionEndReason.COMPROMISE == "compromise"


# --- RefreshToken ---


class TestRefreshToken:
    def test_valid_creation(self):
        token = RefreshToken(
            token_hash="$hash",
            expires_at=datetime(2026, 6, 1, tzinfo=UTC),
            is_revoked=False,
        )
        assert token.token_hash == "$hash"

    def test_rejects_empty_hash(self):
        with pytest.raises(ValueError):
            RefreshToken(
                token_hash="",
                expires_at=datetime(2026, 6, 1, tzinfo=UTC),
                is_revoked=False,
            )

    def test_rejects_exceeding_max_hash_length(self):
        with pytest.raises(ValueError):
            RefreshToken(
                token_hash="x" * 257,
                expires_at=datetime(2026, 6, 1, tzinfo=UTC),
                is_revoked=False,
            )

    def test_is_expired_true_when_past(self):
        expires_at = datetime(2026, 1, 1, tzinfo=UTC)
        token = RefreshToken(token_hash="$h", expires_at=expires_at, is_revoked=False)
        after = expires_at + timedelta(minutes=1)
        assert token.is_expired(after) is True

    def test_is_expired_false_when_future(self):
        expires_at = datetime(2026, 6, 1, tzinfo=UTC)
        token = RefreshToken(token_hash="$h", expires_at=expires_at, is_revoked=False)
        before = expires_at - timedelta(minutes=1)
        assert token.is_expired(before) is False

    def test_guard_not_expired_passes(self):
        expires_at = datetime(2026, 6, 1, tzinfo=UTC)
        token = RefreshToken(token_hash="$h", expires_at=expires_at, is_revoked=False)
        before = expires_at - timedelta(minutes=1)
        token.guard_not_expired(before)

    def test_guard_not_expired_raises(self):
        expires_at = datetime(2026, 1, 1, tzinfo=UTC)
        token = RefreshToken(token_hash="$h", expires_at=expires_at, is_revoked=False)
        after = expires_at + timedelta(minutes=1)
        with pytest.raises(RefreshTokenExpiredError):
            token.guard_not_expired(after)

    def test_guard_not_revoked_passes(self):
        token = RefreshToken(
            token_hash="$h",
            expires_at=datetime(2026, 6, 1, tzinfo=UTC),
            is_revoked=False,
        )
        token.guard_not_revoked()

    def test_guard_not_revoked_raises(self):
        token = RefreshToken(
            token_hash="$h",
            expires_at=datetime(2026, 6, 1, tzinfo=UTC),
            is_revoked=True,
        )
        with pytest.raises(RefreshTokenRevokedError):
            token.guard_not_revoked()

from datetime import datetime

import pytest

from pydentity.authentication.domain.session.aggregate import Session
from pydentity.authentication.domain.session.aggregate_id import SessionId
from pydentity.authentication.domain.session.errors import (
    RefreshTokenExpiredError,
    RefreshTokenRevokedError,
    SessionAlreadyEndedError,
)
from pydentity.authentication.domain.session.events import (
    RefreshTokenRotated,
    SessionEnded,
    SessionStarted,
)
from pydentity.authentication.domain.session.value_objects import (
    RefreshToken,
    SessionEndReason,
    SessionStatus,
)
from pydentity.shared_kernel import AccountId

# --- Factory ---


class TestSessionStart:
    def test_creates_active_session(
        self,
        session_id: SessionId,
        account_id: AccountId,
        refresh_token: RefreshToken,
        now: datetime,
    ):
        session = Session.start(session_id, account_id, refresh_token, now)
        assert session.status == SessionStatus.ACTIVE

    def test_records_session_started_event(
        self,
        session_id: SessionId,
        account_id: AccountId,
        refresh_token: RefreshToken,
        now: datetime,
    ):
        session = Session.start(session_id, account_id, refresh_token, now)
        assert len(session.events) == 1
        assert isinstance(session.events[0], SessionStarted)

    def test_stores_account_id(
        self,
        session_id: SessionId,
        account_id: AccountId,
        refresh_token: RefreshToken,
        now: datetime,
    ):
        session = Session.start(session_id, account_id, refresh_token, now)
        assert session.account_id == account_id

    def test_stores_refresh_token(
        self,
        session_id: SessionId,
        account_id: AccountId,
        refresh_token: RefreshToken,
        now: datetime,
    ):
        session = Session.start(session_id, account_id, refresh_token, now)
        assert session.refresh_token == refresh_token


# --- Refresh ---


class TestSessionRefresh:
    def test_rotates_token(
        self,
        active_session: Session,
        new_refresh_token: RefreshToken,
        now: datetime,
    ):
        active_session.refresh(new_refresh_token, now)
        assert active_session.refresh_token == new_refresh_token

    def test_records_refresh_token_rotated_event(
        self,
        active_session: Session,
        new_refresh_token: RefreshToken,
        now: datetime,
    ):
        active_session.refresh(new_refresh_token, now)
        assert isinstance(active_session.events[0], RefreshTokenRotated)

    def test_raises_when_session_ended(
        self,
        ended_session: Session,
        new_refresh_token: RefreshToken,
        now: datetime,
    ):
        with pytest.raises(SessionAlreadyEndedError):
            ended_session.refresh(new_refresh_token, now)

    def test_raises_when_token_expired(
        self,
        session_id: SessionId,
        account_id: AccountId,
        expired_refresh_token: RefreshToken,
        now: datetime,
    ):
        session = Session.start(session_id, account_id, expired_refresh_token, now)
        session.clear_events()
        new_token = RefreshToken(token_hash="$new", expires_at=now, is_revoked=False)
        with pytest.raises(RefreshTokenExpiredError):
            session.refresh(new_token, now)

    def test_raises_when_token_revoked(
        self,
        session_id: SessionId,
        account_id: AccountId,
        revoked_refresh_token: RefreshToken,
        now: datetime,
    ):
        session = Session.start(session_id, account_id, revoked_refresh_token, now)
        session.clear_events()
        new_token = RefreshToken(token_hash="$new", expires_at=now, is_revoked=False)
        with pytest.raises(RefreshTokenRevokedError):
            session.refresh(new_token, now)


# --- Termination ---


class TestSessionTermination:
    def test_end_transitions_to_ended(self, active_session: Session, now: datetime):
        active_session.end(now)
        assert active_session.status == SessionStatus.ENDED

    def test_end_records_session_ended_with_logout_reason(
        self, active_session: Session, now: datetime
    ):
        active_session.end(now)
        event = active_session.events[0]
        assert isinstance(event, SessionEnded)
        assert event.reason == SessionEndReason.LOGOUT

    def test_idle_timeout_records_correct_reason(
        self, active_session: Session, now: datetime
    ):
        active_session.idle_timeout(now)
        event = active_session.events[0]
        assert isinstance(event, SessionEnded)
        assert event.reason == SessionEndReason.IDLE_TIMEOUT

    def test_absolute_timeout_records_correct_reason(
        self, active_session: Session, now: datetime
    ):
        active_session.absolute_timeout(now)
        event = active_session.events[0]
        assert isinstance(event, SessionEnded)
        assert event.reason == SessionEndReason.ABSOLUTE_TIMEOUT

    def test_force_end_records_correct_reason(
        self, active_session: Session, now: datetime
    ):
        active_session.force_end(now)
        event = active_session.events[0]
        assert isinstance(event, SessionEnded)
        assert event.reason == SessionEndReason.FORCED

    def test_flag_compromised_records_correct_reason(
        self, active_session: Session, now: datetime
    ):
        active_session.flag_compromised(now)
        event = active_session.events[0]
        assert isinstance(event, SessionEnded)
        assert event.reason == SessionEndReason.COMPROMISE

    def test_end_raises_when_already_ended(self, ended_session: Session, now: datetime):
        with pytest.raises(SessionAlreadyEndedError):
            ended_session.end(now)

    def test_idle_timeout_raises_when_already_ended(
        self, ended_session: Session, now: datetime
    ):
        with pytest.raises(SessionAlreadyEndedError):
            ended_session.idle_timeout(now)

    def test_force_end_raises_when_already_ended(
        self, ended_session: Session, now: datetime
    ):
        with pytest.raises(SessionAlreadyEndedError):
            ended_session.force_end(now)

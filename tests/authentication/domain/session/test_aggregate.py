from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from pydentity.authentication.domain.session.aggregate import Session
from pydentity.authentication.domain.session.errors import SessionNotActiveError
from pydentity.authentication.domain.session.events import (
    SessionRefreshed,
    SessionRevoked,
    SessionStarted,
)
from pydentity.authentication.domain.session.value_objects import (
    SessionExpiry,
    SessionId,
    SessionPolicy,
    SessionRevocationReason,
    SessionStatus,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


def _make_session() -> Session:
    return Session.create(
        session_id=SessionId(value=uuid4()),
        account_id=AccountId(value=uuid4()),
        device_id=DeviceId(value=uuid4()),
        expiry=SessionExpiry(
            value=datetime.now(UTC) + timedelta(hours=1),
        ),
    )


class TestSessionCreate:
    def test_create_returns_active_status(self):
        session = _make_session()
        assert session.status == SessionStatus.ACTIVE

    def test_create_returns_correct_fields(self):
        sid = SessionId(value=uuid4())
        aid = AccountId(value=uuid4())
        did = DeviceId(value=uuid4())
        expiry = SessionExpiry(
            value=datetime.now(UTC) + timedelta(hours=1),
        )

        session = Session.create(
            session_id=sid,
            account_id=aid,
            device_id=did,
            expiry=expiry,
        )

        assert session.id == sid
        assert session.account_id == aid
        assert session.device_id == did
        assert session.expiry == expiry

    def test_create_records_session_started_event(self):
        session = _make_session()
        events = session.events
        assert len(events) == 1
        assert isinstance(events[0], SessionStarted)


class TestSessionAggregate:
    def test_is_aggregate_root(self):
        session = _make_session()
        assert isinstance(session, AggregateRoot)

    def test_identity_equality(self):
        uid = uuid4()
        sid = SessionId(value=uid)
        a = Session.create(
            session_id=sid,
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
            expiry=SessionExpiry(
                value=datetime.now(UTC) + timedelta(hours=1),
            ),
        )
        b = Session.create(
            session_id=sid,
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
            expiry=SessionExpiry(
                value=datetime.now(UTC) + timedelta(hours=2),
            ),
        )
        assert a == b

    def test_different_id_not_equal(self):
        a = _make_session()
        b = _make_session()
        assert a != b

    def test_clear_events(self):
        session = _make_session()
        assert len(session.events) == 1
        session.clear_events()
        assert session.events == []


class TestRevoke:
    def test_transitions_to_revoked(self):
        session = _make_session()
        session.revoke(SessionRevocationReason.LOGOUT)
        assert session.status == SessionStatus.REVOKED

    def test_records_session_revoked_event(self):
        session = _make_session()
        session.clear_events()
        session.revoke(SessionRevocationReason.EXPIRED)
        events = session.events
        assert len(events) == 1
        assert isinstance(events[0], SessionRevoked)

    def test_session_revoked_event_carries_reason(self):
        session = _make_session()
        session.clear_events()
        session.revoke(SessionRevocationReason.COMPROMISE)
        event = session.events[0]
        assert isinstance(event, SessionRevoked)
        assert event.reason == SessionRevocationReason.COMPROMISE

    def test_from_revoked_raises(self):
        session = _make_session()
        session.revoke(SessionRevocationReason.LOGOUT)
        with pytest.raises(SessionNotActiveError):
            session.revoke(SessionRevocationReason.FORCED)


class TestRefresh:
    def test_updates_expiry(self):
        session = _make_session()
        old_expiry = session.expiry
        policy = SessionPolicy(ttl_seconds=7200)
        session.refresh(policy, datetime.now(UTC))
        assert session.expiry != old_expiry

    def test_new_expiry_is_in_the_future(self):
        session = _make_session()
        policy = SessionPolicy(ttl_seconds=3600)
        session.refresh(policy, datetime.now(UTC))
        assert session.expiry.value > datetime.now(UTC)

    def test_records_session_refreshed_event(self):
        session = _make_session()
        session.clear_events()
        policy = SessionPolicy(ttl_seconds=3600)
        session.refresh(policy, datetime.now(UTC))
        events = session.events
        assert len(events) == 1
        assert isinstance(events[0], SessionRefreshed)

    def test_stays_active(self):
        session = _make_session()
        policy = SessionPolicy(ttl_seconds=3600)
        session.refresh(policy, datetime.now(UTC))
        assert session.status == SessionStatus.ACTIVE

    def test_from_revoked_raises(self):
        session = _make_session()
        session.revoke(SessionRevocationReason.LOGOUT)
        with pytest.raises(SessionNotActiveError):
            session.refresh(SessionPolicy(ttl_seconds=3600), datetime.now(UTC))

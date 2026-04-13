from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.authentication.domain.session.events import (
    SessionRefreshed,
    SessionRevoked,
    SessionStarted,
)
from pydentity.authentication.domain.session.value_objects import (
    SessionId,
    SessionRevocationReason,
)
from pydentity.shared_kernel.building_blocks import DomainEvent, EventName
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


class TestSessionStarted:
    def test_creation_with_correct_fields(self):
        sid = SessionId(value=uuid4())
        aid = AccountId(value=uuid4())
        did = DeviceId(value=uuid4())
        event = SessionStarted(
            session_id=sid,
            account_id=aid,
            device_id=did,
        )
        assert event.session_id == sid
        assert event.account_id == aid
        assert event.device_id == did

    def test_frozen(self):
        sid = SessionId(value=uuid4())
        aid = AccountId(value=uuid4())
        did = DeviceId(value=uuid4())
        event = SessionStarted(
            session_id=sid,
            account_id=aid,
            device_id=did,
        )
        with pytest.raises(FrozenInstanceError):
            event.session_id = sid  # type: ignore[misc]

    def test_is_domain_event(self):
        event = SessionStarted(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = SessionStarted(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
        )
        assert event.name == EventName("SessionStarted")


class TestSessionRevoked:
    def test_creation_with_correct_fields(self):
        sid = SessionId(value=uuid4())
        aid = AccountId(value=uuid4())
        did = DeviceId(value=uuid4())
        reason = SessionRevocationReason.LOGOUT
        event = SessionRevoked(
            session_id=sid,
            account_id=aid,
            device_id=did,
            reason=reason,
        )
        assert event.session_id == sid
        assert event.account_id == aid
        assert event.device_id == did
        assert event.reason == reason

    def test_frozen(self):
        event = SessionRevoked(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
            reason=SessionRevocationReason.EXPIRED,
        )
        with pytest.raises(FrozenInstanceError):
            event.reason = SessionRevocationReason.FORCED  # type: ignore[misc]

    def test_is_domain_event(self):
        event = SessionRevoked(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
            reason=SessionRevocationReason.COMPROMISE,
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = SessionRevoked(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
            reason=SessionRevocationReason.FORCED,
        )
        assert event.name == EventName("SessionRevoked")


class TestSessionRefreshed:
    def test_creation_with_correct_fields(self):
        sid = SessionId(value=uuid4())
        aid = AccountId(value=uuid4())
        did = DeviceId(value=uuid4())
        event = SessionRefreshed(
            session_id=sid,
            account_id=aid,
            device_id=did,
        )
        assert event.session_id == sid
        assert event.account_id == aid
        assert event.device_id == did

    def test_frozen(self):
        event = SessionRefreshed(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
        )
        with pytest.raises(FrozenInstanceError):
            event.session_id = SessionId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = SessionRefreshed(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = SessionRefreshed(
            session_id=SessionId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            device_id=DeviceId(value=uuid4()),
        )
        assert event.name == EventName("SessionRefreshed")

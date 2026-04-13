from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from pydentity.authentication.domain.session.value_objects import (
    SessionExpiry,
    SessionId,
    SessionPolicy,
    SessionRevocationReason,
    SessionStatus,
)
from pydentity.shared_kernel.building_blocks import ValueObject


class TestSessionId:
    def test_stores_uuid(self):
        uid = uuid4()
        sid = SessionId(value=uid)
        assert sid.value == uid

    def test_frozen(self):
        sid = SessionId(value=uuid4())
        with pytest.raises(FrozenInstanceError):
            sid.value = uuid4()  # type: ignore[misc]

    def test_equal_by_value(self):
        uid = uuid4()
        assert SessionId(value=uid) == SessionId(value=uid)

    def test_hashable(self):
        uid = uuid4()
        a = SessionId(value=uid)
        b = SessionId(value=uid)
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_is_value_object(self):
        sid = SessionId(value=uuid4())
        assert isinstance(sid, ValueObject)


class TestSessionPolicy:
    def test_stores_ttl(self):
        policy = SessionPolicy(ttl_seconds=3600)
        assert policy.ttl_seconds == 3600

    def test_frozen(self):
        policy = SessionPolicy(ttl_seconds=3600)
        with pytest.raises(FrozenInstanceError):
            policy.ttl_seconds = 7200  # type: ignore[misc]

    def test_equal_by_value(self):
        assert SessionPolicy(ttl_seconds=3600) == SessionPolicy(ttl_seconds=3600)

    def test_is_value_object(self):
        policy = SessionPolicy(ttl_seconds=3600)
        assert isinstance(policy, ValueObject)

    def test_zero_ttl_raises(self):
        with pytest.raises(ValueError):
            SessionPolicy(ttl_seconds=0)

    def test_negative_ttl_raises(self):
        with pytest.raises(ValueError):
            SessionPolicy(ttl_seconds=-1)

    def test_positive_ttl_valid(self):
        policy = SessionPolicy(ttl_seconds=1)
        assert policy.ttl_seconds == 1


class TestSessionExpiry:
    def test_stores_datetime(self):
        now = datetime.now(UTC)
        expiry = SessionExpiry(value=now)
        assert expiry.value == now

    def test_frozen(self):
        expiry = SessionExpiry(value=datetime.now(UTC))
        with pytest.raises(FrozenInstanceError):
            expiry.value = datetime.now(UTC)  # type: ignore[misc]

    def test_equal_by_value(self):
        now = datetime.now(UTC)
        assert SessionExpiry(value=now) == SessionExpiry(value=now)

    def test_is_value_object(self):
        expiry = SessionExpiry(value=datetime.now(UTC))
        assert isinstance(expiry, ValueObject)


class TestSessionStatus:
    def test_has_active(self):
        assert SessionStatus.ACTIVE == "active"

    def test_has_revoked(self):
        assert SessionStatus.REVOKED == "revoked"


class TestSessionRevocationReason:
    def test_has_logout(self):
        assert SessionRevocationReason.LOGOUT == "logout"

    def test_has_expired(self):
        assert SessionRevocationReason.EXPIRED == "expired"

    def test_has_forced(self):
        assert SessionRevocationReason.FORCED == "forced"

    def test_has_compromise(self):
        assert SessionRevocationReason.COMPROMISE == "compromise"

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from pydentity.authentication.domain.verification_request.aggregate import (
    VerificationRequest,
)
from pydentity.authentication.domain.verification_request.errors import (
    VerificationRequestNotPendingError,
)
from pydentity.authentication.domain.verification_request.events import (
    VerificationRequestCreated,
    VerificationRequestExpired,
    VerificationRequestInvalidated,
    VerificationRequestVerified,
)
from pydentity.authentication.domain.verification_request.value_objects import (
    HashedVerificationRequestToken,
    VerificationRequestExpiry,
    VerificationRequestId,
    VerificationRequestStatus,
    VerificationRequestType,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot
from pydentity.shared_kernel.value_objects import AccountId


def _future_expiry() -> VerificationRequestExpiry:
    return VerificationRequestExpiry(
        value=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def _make_request(
    expiry: VerificationRequestExpiry | None = None,
    request_type: VerificationRequestType = VerificationRequestType.EMAIL_VERIFICATION,
) -> VerificationRequest:
    return VerificationRequest.create(
        verification_request_id=VerificationRequestId(value=uuid4()),
        account_id=AccountId(value=uuid4()),
        request_type=request_type,
        hashed_token=HashedVerificationRequestToken(value="hashed-token"),
        expiry=expiry or _future_expiry(),
    )


class TestVerificationRequestCreate:
    def test_create_returns_pending_status(self):
        request = _make_request()
        assert request.status == VerificationRequestStatus.PENDING

    def test_create_records_created_event(self):
        request = _make_request()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], VerificationRequestCreated)

    def test_created_event_has_correct_fields(self):
        rid = VerificationRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        rtype = VerificationRequestType.PASSWORD_RESET
        request = VerificationRequest.create(
            verification_request_id=rid,
            account_id=aid,
            request_type=rtype,
            hashed_token=HashedVerificationRequestToken(value="h"),
            expiry=_future_expiry(),
        )
        event = request.events[0]
        assert isinstance(event, VerificationRequestCreated)
        assert event.verification_request_id == rid
        assert event.account_id == aid
        assert event.request_type == rtype

    def test_create_returns_correct_fields(self):
        rid = VerificationRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        rtype = VerificationRequestType.EMAIL_VERIFICATION
        hashed = HashedVerificationRequestToken(value="h")
        expiry = _future_expiry()

        request = VerificationRequest.create(
            verification_request_id=rid,
            account_id=aid,
            request_type=rtype,
            hashed_token=hashed,
            expiry=expiry,
        )

        assert request.id == rid
        assert request.account_id == aid
        assert request.request_type == rtype
        assert request.hashed_token == hashed
        assert request.expiry == expiry


class TestVerificationRequestAggregate:
    def test_is_aggregate_root(self):
        request = _make_request()
        assert isinstance(request, AggregateRoot)

    def test_identity_equality(self):
        uid = uuid4()
        rid = VerificationRequestId(value=uid)
        a = VerificationRequest.create(
            verification_request_id=rid,
            account_id=AccountId(value=uuid4()),
            request_type=VerificationRequestType.EMAIL_VERIFICATION,
            hashed_token=HashedVerificationRequestToken(value="h1"),
            expiry=_future_expiry(),
        )
        b = VerificationRequest.create(
            verification_request_id=rid,
            account_id=AccountId(value=uuid4()),
            request_type=VerificationRequestType.PASSWORD_RESET,
            hashed_token=HashedVerificationRequestToken(value="h2"),
            expiry=_future_expiry(),
        )
        assert a == b

    def test_different_id_not_equal(self):
        a = _make_request()
        b = _make_request()
        assert a != b

    def test_clear_events(self):
        request = _make_request()
        assert len(request.events) == 1
        request.clear_events()
        assert request.events == []


class TestVerify:
    def test_transitions_to_verified(self):
        request = _make_request()
        request.verify()
        assert request.status == VerificationRequestStatus.VERIFIED

    def test_records_verified_event(self):
        request = _make_request()
        request.clear_events()
        request.verify()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], VerificationRequestVerified)

    def test_not_pending_raises(self):
        request = _make_request()
        request.invalidate()
        with pytest.raises(VerificationRequestNotPendingError):
            request.verify()

    def test_verified_cannot_verify_again(self):
        request = _make_request()
        request.verify()
        with pytest.raises(VerificationRequestNotPendingError):
            request.verify()

    def test_expired_cannot_verify(self):
        request = _make_request()
        request.expire()
        with pytest.raises(VerificationRequestNotPendingError):
            request.verify()


class TestInvalidate:
    def test_transitions_to_invalidated(self):
        request = _make_request()
        request.invalidate()
        assert request.status == VerificationRequestStatus.INVALIDATED

    def test_records_invalidated_event(self):
        request = _make_request()
        request.clear_events()
        request.invalidate()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], VerificationRequestInvalidated)

    def test_from_verified_raises(self):
        request = _make_request()
        request.verify()
        with pytest.raises(VerificationRequestNotPendingError):
            request.invalidate()

    def test_from_invalidated_raises(self):
        request = _make_request()
        request.invalidate()
        with pytest.raises(VerificationRequestNotPendingError):
            request.invalidate()

    def test_from_expired_raises(self):
        request = _make_request()
        request.expire()
        with pytest.raises(VerificationRequestNotPendingError):
            request.invalidate()


class TestExpire:
    def test_transitions_to_expired(self):
        request = _make_request()
        request.expire()
        assert request.status == VerificationRequestStatus.EXPIRED

    def test_records_expired_event(self):
        request = _make_request()
        request.clear_events()
        request.expire()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], VerificationRequestExpired)

    def test_from_verified_raises(self):
        request = _make_request()
        request.verify()
        with pytest.raises(VerificationRequestNotPendingError):
            request.expire()

    def test_from_invalidated_raises(self):
        request = _make_request()
        request.invalidate()
        with pytest.raises(VerificationRequestNotPendingError):
            request.expire()

    def test_from_expired_raises(self):
        request = _make_request()
        request.expire()
        with pytest.raises(VerificationRequestNotPendingError):
            request.expire()

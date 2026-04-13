from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.authentication.domain.verification_request.events import (
    VerificationRequestCreated,
    VerificationRequestExpired,
    VerificationRequestFailed,
    VerificationRequestInvalidated,
    VerificationRequestVerified,
)
from pydentity.authentication.domain.verification_request.value_objects import (
    VerificationFailureReason,
    VerificationRequestId,
    VerificationRequestType,
)
from pydentity.shared_kernel.building_blocks import DomainEvent, EventName
from pydentity.shared_kernel.value_objects import AccountId


class TestVerificationRequestCreated:
    def test_creation_with_correct_fields(self):
        rid = VerificationRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        rtype = VerificationRequestType.EMAIL_VERIFICATION
        event = VerificationRequestCreated(
            verification_request_id=rid,
            account_id=aid,
            request_type=rtype,
        )
        assert event.verification_request_id == rid
        assert event.account_id == aid
        assert event.request_type == rtype

    def test_frozen(self):
        event = VerificationRequestCreated(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            request_type=VerificationRequestType.EMAIL_VERIFICATION,
        )
        with pytest.raises(FrozenInstanceError):
            event.verification_request_id = VerificationRequestId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = VerificationRequestCreated(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            request_type=VerificationRequestType.EMAIL_VERIFICATION,
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = VerificationRequestCreated(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            request_type=VerificationRequestType.EMAIL_VERIFICATION,
        )
        assert event.name == EventName("VerificationRequestCreated")


class TestVerificationRequestVerified:
    def test_creation_with_correct_fields(self):
        rid = VerificationRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = VerificationRequestVerified(
            verification_request_id=rid,
            account_id=aid,
        )
        assert event.verification_request_id == rid
        assert event.account_id == aid

    def test_frozen(self):
        event = VerificationRequestVerified(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        with pytest.raises(FrozenInstanceError):
            event.verification_request_id = VerificationRequestId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = VerificationRequestVerified(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = VerificationRequestVerified(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert event.name == EventName("VerificationRequestVerified")


class TestVerificationRequestFailed:
    def test_creation_with_correct_fields(self):
        rid = VerificationRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        reason = VerificationFailureReason.INVALID_TOKEN
        event = VerificationRequestFailed(
            verification_request_id=rid,
            account_id=aid,
            reason=reason,
        )
        assert event.verification_request_id == rid
        assert event.account_id == aid
        assert event.reason == reason

    def test_frozen(self):
        event = VerificationRequestFailed(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            reason=VerificationFailureReason.EXPIRED,
        )
        with pytest.raises(FrozenInstanceError):
            event.reason = VerificationFailureReason.INVALID_TOKEN  # type: ignore[misc]

    def test_is_domain_event(self):
        event = VerificationRequestFailed(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            reason=VerificationFailureReason.EXPIRED,
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = VerificationRequestFailed(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            reason=VerificationFailureReason.EXPIRED,
        )
        assert event.name == EventName("VerificationRequestFailed")


class TestVerificationRequestInvalidated:
    def test_creation_with_correct_fields(self):
        rid = VerificationRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = VerificationRequestInvalidated(
            verification_request_id=rid,
            account_id=aid,
        )
        assert event.verification_request_id == rid
        assert event.account_id == aid

    def test_frozen(self):
        event = VerificationRequestInvalidated(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        with pytest.raises(FrozenInstanceError):
            event.verification_request_id = VerificationRequestId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = VerificationRequestInvalidated(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = VerificationRequestInvalidated(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert event.name == EventName("VerificationRequestInvalidated")


class TestVerificationRequestExpired:
    def test_creation_with_correct_fields(self):
        rid = VerificationRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = VerificationRequestExpired(
            verification_request_id=rid,
            account_id=aid,
        )
        assert event.verification_request_id == rid
        assert event.account_id == aid

    def test_frozen(self):
        event = VerificationRequestExpired(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        with pytest.raises(FrozenInstanceError):
            event.verification_request_id = VerificationRequestId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = VerificationRequestExpired(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = VerificationRequestExpired(
            verification_request_id=VerificationRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert event.name == EventName("VerificationRequestExpired")

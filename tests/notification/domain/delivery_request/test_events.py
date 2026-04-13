from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.notification.domain.delivery_request.events import (
    ContentPurged,
    DeliveryAttemptFailed,
    DeliveryRequestCreated,
    MessageDelivered,
    MessageDeliveryFailed,
)
from pydentity.notification.domain.delivery_request.value_objects import (
    AttemptCount,
    Channel,
    DeliveryRequestId,
)
from pydentity.shared_kernel.building_blocks import DomainEvent, EventName
from pydentity.shared_kernel.value_objects import AccountId


class TestDeliveryRequestCreated:
    def test_creation_with_correct_fields(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = DeliveryRequestCreated(
            delivery_request_id=rid,
            account_id=aid,
            channel=Channel.EMAIL,
        )
        assert event.delivery_request_id == rid
        assert event.account_id == aid
        assert event.channel == Channel.EMAIL

    def test_frozen(self):
        event = DeliveryRequestCreated(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            channel=Channel.SMS,
        )
        with pytest.raises(FrozenInstanceError):
            event.delivery_request_id = DeliveryRequestId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = DeliveryRequestCreated(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            channel=Channel.EMAIL,
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = DeliveryRequestCreated(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            channel=Channel.EMAIL,
        )
        assert event.name == EventName("DeliveryRequestCreated")


class TestMessageDelivered:
    def test_creation_with_correct_fields(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = MessageDelivered(
            delivery_request_id=rid,
            account_id=aid,
        )
        assert event.delivery_request_id == rid
        assert event.account_id == aid

    def test_frozen(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = MessageDelivered(
            delivery_request_id=rid,
            account_id=aid,
        )
        with pytest.raises(FrozenInstanceError):
            event.delivery_request_id = rid  # type: ignore[misc]

    def test_is_domain_event(self):
        event = MessageDelivered(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = MessageDelivered(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert event.name == EventName("MessageDelivered")


class TestDeliveryAttemptFailed:
    def test_creation_with_correct_fields(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        count = AttemptCount(value=3)
        event = DeliveryAttemptFailed(
            delivery_request_id=rid,
            account_id=aid,
            attempt_count=count,
        )
        assert event.delivery_request_id == rid
        assert event.account_id == aid
        assert event.attempt_count == count

    def test_frozen(self):
        event = DeliveryAttemptFailed(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            attempt_count=AttemptCount(value=1),
        )
        with pytest.raises(FrozenInstanceError):
            event.delivery_request_id = DeliveryRequestId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = DeliveryAttemptFailed(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            attempt_count=AttemptCount(value=0),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = DeliveryAttemptFailed(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            attempt_count=AttemptCount(value=0),
        )
        assert event.name == EventName("DeliveryAttemptFailed")


class TestMessageDeliveryFailed:
    def test_creation_with_correct_fields(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = MessageDeliveryFailed(
            delivery_request_id=rid,
            account_id=aid,
        )
        assert event.delivery_request_id == rid
        assert event.account_id == aid

    def test_frozen(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = MessageDeliveryFailed(
            delivery_request_id=rid,
            account_id=aid,
        )
        with pytest.raises(FrozenInstanceError):
            event.delivery_request_id = rid  # type: ignore[misc]

    def test_is_domain_event(self):
        event = MessageDeliveryFailed(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = MessageDeliveryFailed(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert event.name == EventName("MessageDeliveryFailed")


class TestContentPurged:
    def test_creation_with_correct_fields(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = ContentPurged(
            delivery_request_id=rid,
            account_id=aid,
        )
        assert event.delivery_request_id == rid
        assert event.account_id == aid

    def test_frozen(self):
        event = ContentPurged(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        with pytest.raises(FrozenInstanceError):
            event.delivery_request_id = DeliveryRequestId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = ContentPurged(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = ContentPurged(
            delivery_request_id=DeliveryRequestId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert event.name == EventName("ContentPurged")

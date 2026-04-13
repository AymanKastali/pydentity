from uuid import uuid4

import pytest

from pydentity.notification.domain.delivery_request.aggregate import DeliveryRequest
from pydentity.notification.domain.delivery_request.errors import (
    ContentPurgeRequiresSensitiveError,
    ContentPurgeRequiresSentError,
    DeliveryRequestNotPendingError,
)
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
    ContentSensitivity,
    DeliveryRequestId,
    DeliveryStatus,
    MessageContent,
    Recipient,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot
from pydentity.shared_kernel.value_objects import AccountId


def _make_request(
    sensitivity: ContentSensitivity = ContentSensitivity.STANDARD,
) -> DeliveryRequest:
    return DeliveryRequest.create(
        delivery_request_id=DeliveryRequestId(value=uuid4()),
        account_id=AccountId(value=uuid4()),
        recipient=Recipient(address="user@example.com"),
        channel=Channel.EMAIL,
        content=MessageContent(subject="Welcome", body="Hello there"),
        sensitivity=sensitivity,
    )


class TestDeliveryRequestCreate:
    def test_create_returns_pending_status(self):
        request = _make_request()
        assert request.status == DeliveryStatus.PENDING

    def test_create_returns_zero_attempt_count(self):
        request = _make_request()
        assert request.attempt_count == AttemptCount(0)

    def test_create_returns_correct_fields(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        recipient = Recipient(address="test@test.com")
        channel = Channel.SMS
        content = MessageContent(subject=None, body="Code: 1234")
        sensitivity = ContentSensitivity.SENSITIVE

        request = DeliveryRequest.create(
            delivery_request_id=rid,
            account_id=aid,
            recipient=recipient,
            channel=channel,
            content=content,
            sensitivity=sensitivity,
        )

        assert request.id == rid
        assert request.account_id == aid
        assert request.recipient == recipient
        assert request.channel == channel
        assert request.content == content
        assert request.sensitivity == sensitivity


class TestDeliveryRequestAggregate:
    def test_is_aggregate_root(self):
        request = _make_request()
        assert isinstance(request, AggregateRoot)

    def test_identity_equality(self):
        uid = uuid4()
        rid = DeliveryRequestId(value=uid)
        a = DeliveryRequest.create(
            delivery_request_id=rid,
            account_id=AccountId(value=uuid4()),
            recipient=Recipient(address="a@a.com"),
            channel=Channel.EMAIL,
            content=MessageContent(subject=None, body="body"),
            sensitivity=ContentSensitivity.STANDARD,
        )
        b = DeliveryRequest.create(
            delivery_request_id=rid,
            account_id=AccountId(value=uuid4()),
            recipient=Recipient(address="b@b.com"),
            channel=Channel.SMS,
            content=MessageContent(subject=None, body="other"),
            sensitivity=ContentSensitivity.SENSITIVE,
        )
        assert a == b

    def test_different_id_not_equal(self):
        a = _make_request()
        b = _make_request()
        assert a != b

    def test_create_records_created_event(self):
        request = _make_request()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], DeliveryRequestCreated)

    def test_created_event_has_correct_fields(self):
        rid = DeliveryRequestId(value=uuid4())
        aid = AccountId(value=uuid4())
        request = DeliveryRequest.create(
            delivery_request_id=rid,
            account_id=aid,
            recipient=Recipient(address="user@example.com"),
            channel=Channel.SMS,
            content=MessageContent(subject=None, body="Hello"),
            sensitivity=ContentSensitivity.STANDARD,
        )
        event = request.events[0]
        assert isinstance(event, DeliveryRequestCreated)
        assert event.delivery_request_id == rid
        assert event.account_id == aid
        assert event.channel == Channel.SMS

    def test_clear_events(self):
        request = _make_request()
        assert len(request.events) == 1
        request.clear_events()
        assert request.events == []


class TestMarkSent:
    def test_transitions_to_sent(self):
        request = _make_request()
        request.mark_sent()
        assert request.status == DeliveryStatus.SENT

    def test_records_message_delivered_event(self):
        request = _make_request()
        request.clear_events()
        request.mark_sent()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], MessageDelivered)

    def test_from_sent_raises(self):
        request = _make_request()
        request.mark_sent()
        with pytest.raises(DeliveryRequestNotPendingError):
            request.mark_sent()

    def test_from_failed_raises(self):
        request = _make_request()
        request.mark_failed()
        with pytest.raises(DeliveryRequestNotPendingError):
            request.mark_sent()


class TestRecordFailedAttempt:
    def test_increments_attempt_count(self):
        request = _make_request()
        request.record_failed_attempt()
        assert request.attempt_count == AttemptCount(1)
        request.record_failed_attempt()
        assert request.attempt_count == AttemptCount(2)

    def test_stays_pending(self):
        request = _make_request()
        request.record_failed_attempt()
        assert request.status == DeliveryStatus.PENDING

    def test_records_delivery_attempt_failed_event(self):
        request = _make_request()
        request.clear_events()
        request.record_failed_attempt()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], DeliveryAttemptFailed)

    def test_event_carries_attempt_count(self):
        request = _make_request()
        request.clear_events()
        request.record_failed_attempt()
        event = request.events[0]
        assert isinstance(event, DeliveryAttemptFailed)
        assert event.attempt_count == AttemptCount(1)

    def test_from_sent_raises(self):
        request = _make_request()
        request.mark_sent()
        with pytest.raises(DeliveryRequestNotPendingError):
            request.record_failed_attempt()

    def test_from_failed_raises(self):
        request = _make_request()
        request.mark_failed()
        with pytest.raises(DeliveryRequestNotPendingError):
            request.record_failed_attempt()


class TestMarkFailed:
    def test_transitions_to_failed(self):
        request = _make_request()
        request.mark_failed()
        assert request.status == DeliveryStatus.FAILED

    def test_records_message_delivery_failed_event(self):
        request = _make_request()
        request.clear_events()
        request.mark_failed()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], MessageDeliveryFailed)

    def test_from_sent_raises(self):
        request = _make_request()
        request.mark_sent()
        with pytest.raises(DeliveryRequestNotPendingError):
            request.mark_failed()

    def test_from_failed_raises(self):
        request = _make_request()
        request.mark_failed()
        with pytest.raises(DeliveryRequestNotPendingError):
            request.mark_failed()


class TestPurgeContent:
    def test_sets_content_to_none(self):
        request = _make_request(sensitivity=ContentSensitivity.SENSITIVE)
        request.mark_sent()
        request.purge_content()
        assert request.content is None

    def test_records_content_purged_event(self):
        request = _make_request(sensitivity=ContentSensitivity.SENSITIVE)
        request.mark_sent()
        request.clear_events()
        request.purge_content()
        events = request.events
        assert len(events) == 1
        assert isinstance(events[0], ContentPurged)

    def test_when_not_sent_raises(self):
        request = _make_request(sensitivity=ContentSensitivity.SENSITIVE)
        with pytest.raises(ContentPurgeRequiresSentError):
            request.purge_content()

    def test_when_failed_raises(self):
        request = _make_request(sensitivity=ContentSensitivity.SENSITIVE)
        request.mark_failed()
        with pytest.raises(ContentPurgeRequiresSentError):
            request.purge_content()

    def test_when_not_sensitive_raises(self):
        request = _make_request(sensitivity=ContentSensitivity.STANDARD)
        request.mark_sent()
        with pytest.raises(ContentPurgeRequiresSensitiveError):
            request.purge_content()

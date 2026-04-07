from datetime import datetime

import pytest

from pydentity.notification.domain.delivery_request.aggregate import DeliveryRequest
from pydentity.notification.domain.delivery_request.errors import (
    DeliveryRequestAlreadyFailedError,
    DeliveryRequestAlreadySentError,
    DeliveryRequestContentAlreadyPurgedError,
    DeliveryRequestNotSensitiveError,
)
from pydentity.notification.domain.delivery_request.events import (
    MessageDelivered,
    MessageDeliveryFailed,
)
from pydentity.notification.domain.delivery_request.value_objects import (
    AttemptCount,
    Channel,
    ContentSensitivity,
    DeliveryStatus,
)

# --- Factory ---


class TestDeliveryRequestCreate:
    def test_creates_pending_delivery(self, pending_delivery: DeliveryRequest):
        assert pending_delivery.status == DeliveryStatus.PENDING

    def test_stores_recipient_and_channel(self, pending_delivery: DeliveryRequest):
        assert pending_delivery.recipient.address == "user@example.com"
        assert pending_delivery.channel == Channel.EMAIL

    def test_initializes_zero_attempt_count(self, pending_delivery: DeliveryRequest):
        assert pending_delivery.attempt_count == AttemptCount.initialize()

    def test_stores_sensitivity(
        self,
        pending_delivery: DeliveryRequest,
        sensitive_pending_delivery: DeliveryRequest,
    ):
        assert pending_delivery.sensitivity is ContentSensitivity.STANDARD
        assert sensitive_pending_delivery.sensitivity is ContentSensitivity.SENSITIVE


# --- Mark sent ---


class TestMarkSent:
    def test_transitions_to_sent(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_sent(now)
        assert pending_delivery.status == DeliveryStatus.SENT

    def test_increments_attempt_count(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_sent(now)
        assert pending_delivery.attempt_count == AttemptCount(value=1)

    def test_records_message_delivered_event(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_sent(now)
        assert isinstance(pending_delivery.events[0], MessageDelivered)

    def test_raises_when_already_sent(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_sent(now)
        with pytest.raises(DeliveryRequestAlreadySentError):
            pending_delivery.mark_sent(now)

    def test_raises_when_already_failed(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_failed(now)
        with pytest.raises(DeliveryRequestAlreadyFailedError):
            pending_delivery.mark_sent(now)


# --- Record failed attempt ---


class TestRecordFailedAttempt:
    def test_increments_count(self, pending_delivery: DeliveryRequest):
        pending_delivery.record_failed_attempt()
        assert pending_delivery.attempt_count == AttemptCount(value=1)

    def test_raises_when_already_sent(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_sent(now)
        with pytest.raises(DeliveryRequestAlreadySentError):
            pending_delivery.record_failed_attempt()

    def test_raises_when_already_failed(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_failed(now)
        with pytest.raises(DeliveryRequestAlreadyFailedError):
            pending_delivery.record_failed_attempt()


# --- Mark failed ---


class TestMarkFailed:
    def test_transitions_to_failed(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_failed(now)
        assert pending_delivery.status == DeliveryStatus.FAILED

    def test_records_message_delivery_failed_event(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_failed(now)
        assert isinstance(pending_delivery.events[0], MessageDeliveryFailed)

    def test_raises_when_already_sent(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_sent(now)
        with pytest.raises(DeliveryRequestAlreadySentError):
            pending_delivery.mark_failed(now)

    def test_raises_when_already_failed(
        self,
        pending_delivery: DeliveryRequest,
        now: datetime,
    ):
        pending_delivery.mark_failed(now)
        with pytest.raises(DeliveryRequestAlreadyFailedError):
            pending_delivery.mark_failed(now)


# --- Purge content ---


class TestPurgeContent:
    def test_clears_content_when_sensitive(
        self,
        sensitive_pending_delivery: DeliveryRequest,
    ):
        sensitive_pending_delivery.purge_content()
        assert sensitive_pending_delivery.content is None

    def test_raises_when_not_sensitive(
        self,
        pending_delivery: DeliveryRequest,
    ):
        with pytest.raises(DeliveryRequestNotSensitiveError):
            pending_delivery.purge_content()

    def test_raises_when_already_purged(
        self,
        sensitive_pending_delivery: DeliveryRequest,
    ):
        sensitive_pending_delivery.purge_content()
        with pytest.raises(DeliveryRequestContentAlreadyPurgedError):
            sensitive_pending_delivery.purge_content()

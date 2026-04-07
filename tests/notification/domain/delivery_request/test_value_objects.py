import pytest

from pydentity.notification.domain.delivery_request.errors import (
    DeliveryRequestAlreadyFailedError,
    DeliveryRequestAlreadySentError,
    DeliveryRequestNotSensitiveError,
)
from pydentity.notification.domain.delivery_request.value_objects import (
    AttemptCount,
    Channel,
    ContentSensitivity,
    DeliveryStatus,
    MessageContent,
    Recipient,
)

# --- Channel ---


class TestChannel:
    def test_values(self):
        assert Channel.EMAIL == "email"
        assert Channel.SMS == "sms"


# --- DeliveryStatus ---


class TestDeliveryStatus:
    def test_pending_query(self):
        assert DeliveryStatus.PENDING.is_pending is True

    def test_sent_query(self):
        assert DeliveryStatus.SENT.is_sent is True

    def test_failed_query(self):
        assert DeliveryStatus.FAILED.is_failed is True

    def test_guard_not_sent_passes(self):
        DeliveryStatus.PENDING.guard_not_sent()

    def test_guard_not_sent_raises(self):
        with pytest.raises(DeliveryRequestAlreadySentError):
            DeliveryStatus.SENT.guard_not_sent()

    def test_guard_not_failed_passes(self):
        DeliveryStatus.PENDING.guard_not_failed()

    def test_guard_not_failed_raises(self):
        with pytest.raises(DeliveryRequestAlreadyFailedError):
            DeliveryStatus.FAILED.guard_not_failed()


# --- Recipient ---


class TestRecipient:
    def test_valid_creation(self):
        recipient = Recipient(address="user@example.com")
        assert recipient.address == "user@example.com"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            Recipient(address="")

    def test_rejects_exceeding_max_length(self):
        with pytest.raises(ValueError):
            Recipient(address="x" * 255)


# --- MessageContent ---


class TestMessageContent:
    def test_valid_creation(self):
        content = MessageContent(subject="Subject", body="Body text")
        assert content.subject == "Subject"
        assert content.body == "Body text"

    def test_valid_without_subject(self):
        content = MessageContent(subject=None, body="Body text")
        assert content.subject is None

    def test_rejects_empty_body(self):
        with pytest.raises(ValueError):
            MessageContent(subject="Subject", body="")

    def test_rejects_body_exceeding_max_length(self):
        with pytest.raises(ValueError):
            MessageContent(subject="Subject", body="x" * 50_001)

    def test_rejects_subject_exceeding_max_length(self):
        with pytest.raises(ValueError):
            MessageContent(subject="x" * 201, body="Body")


# --- AttemptCount ---


class TestAttemptCount:
    def test_initializes_to_zero(self):
        count = AttemptCount.initialize()
        assert count.value == 0

    def test_increment_returns_new_instance(self):
        count = AttemptCount.initialize()
        incremented = count.increment()
        assert incremented.value == 1
        assert count.value == 0

    def test_rejects_negative_value(self):
        with pytest.raises(ValueError):
            AttemptCount(value=-1)

    def test_rejects_exceeding_max(self):
        with pytest.raises(ValueError):
            AttemptCount(value=101)

    def test_accepts_max_value(self):
        count = AttemptCount(value=100)
        assert count.value == 100

    def test_equality(self):
        assert AttemptCount(value=3) == AttemptCount(value=3)
        assert AttemptCount(value=3) != AttemptCount(value=4)


# --- ContentSensitivity ---


class TestContentSensitivity:
    def test_sensitive_query(self):
        assert ContentSensitivity.SENSITIVE.is_sensitive is True

    def test_standard_query(self):
        assert ContentSensitivity.STANDARD.is_sensitive is False

    def test_guard_passes_for_sensitive(self):
        ContentSensitivity.SENSITIVE.guard_is_sensitive()

    def test_guard_raises_for_standard(self):
        with pytest.raises(DeliveryRequestNotSensitiveError):
            ContentSensitivity.STANDARD.guard_is_sensitive()

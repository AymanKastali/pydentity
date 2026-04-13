from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.notification.domain.delivery_request.value_objects import (
    AttemptCount,
    Channel,
    ContentSensitivity,
    DeliveryRequestId,
    DeliveryStatus,
    MessageContent,
    Recipient,
)
from pydentity.shared_kernel.building_blocks import ValueObject


class TestDeliveryRequestId:
    def test_stores_uuid(self):
        uid = uuid4()
        rid = DeliveryRequestId(value=uid)
        assert rid.value == uid

    def test_frozen(self):
        rid = DeliveryRequestId(value=uuid4())
        with pytest.raises(FrozenInstanceError):
            rid.value = uuid4()  # type: ignore[misc]

    def test_equal_by_value(self):
        uid = uuid4()
        assert DeliveryRequestId(value=uid) == DeliveryRequestId(value=uid)

    def test_hashable(self):
        uid = uuid4()
        a = DeliveryRequestId(value=uid)
        b = DeliveryRequestId(value=uid)
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_is_value_object(self):
        rid = DeliveryRequestId(value=uuid4())
        assert isinstance(rid, ValueObject)


class TestRecipient:
    def test_valid_creation(self):
        recipient = Recipient(address="user@example.com")
        assert recipient.address == "user@example.com"

    def test_frozen(self):
        recipient = Recipient(address="user@example.com")
        with pytest.raises(FrozenInstanceError):
            recipient.address = "other@example.com"  # type: ignore[misc]

    def test_equal_by_value(self):
        assert Recipient(address="a@b.com") == Recipient(address="a@b.com")

    def test_hashable(self):
        a = Recipient(address="a@b.com")
        b = Recipient(address="a@b.com")
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_is_value_object(self):
        recipient = Recipient(address="user@example.com")
        assert isinstance(recipient, ValueObject)

    def test_blank_address_raises(self):
        with pytest.raises(ValueError):
            Recipient(address="   ")

    def test_empty_address_raises(self):
        with pytest.raises(ValueError):
            Recipient(address="")

    def test_address_over_254_chars_raises(self):
        with pytest.raises(ValueError):
            Recipient(address="a" * 255)

    def test_address_at_254_chars_is_valid(self):
        recipient = Recipient(address="a" * 254)
        assert len(recipient.address) == 254


class TestMessageContent:
    def test_valid_creation_with_subject(self):
        content = MessageContent(subject="Hello", body="World")
        assert content.subject == "Hello"
        assert content.body == "World"

    def test_valid_creation_with_none_subject(self):
        content = MessageContent(subject=None, body="Body text")
        assert content.subject is None
        assert content.body == "Body text"

    def test_frozen(self):
        content = MessageContent(subject="Hello", body="World")
        with pytest.raises(FrozenInstanceError):
            content.body = "other"  # type: ignore[misc]

    def test_equal_by_value(self):
        assert MessageContent(subject="S", body="B") == MessageContent(
            subject="S", body="B"
        )

    def test_is_value_object(self):
        content = MessageContent(subject=None, body="text")
        assert isinstance(content, ValueObject)

    def test_blank_body_raises(self):
        with pytest.raises(ValueError):
            MessageContent(subject=None, body="   ")

    def test_empty_body_raises(self):
        with pytest.raises(ValueError):
            MessageContent(subject=None, body="")

    def test_body_over_50000_chars_raises(self):
        with pytest.raises(ValueError):
            MessageContent(subject=None, body="a" * 50_001)

    def test_subject_over_200_chars_raises(self):
        with pytest.raises(ValueError):
            MessageContent(subject="a" * 201, body="valid body")

    def test_subject_at_200_chars_is_valid(self):
        content = MessageContent(subject="a" * 200, body="valid body")
        assert content.subject is not None
        assert len(content.subject) == 200


class TestAttemptCount:
    def test_stores_int(self):
        count = AttemptCount(value=3)
        assert count.value == 3

    def test_valid_zero(self):
        count = AttemptCount(value=0)
        assert count.value == 0

    def test_frozen(self):
        count = AttemptCount(value=0)
        with pytest.raises(FrozenInstanceError):
            count.value = 1  # type: ignore[misc]

    def test_equal_by_value(self):
        assert AttemptCount(value=5) == AttemptCount(value=5)

    def test_is_value_object(self):
        count = AttemptCount(value=0)
        assert isinstance(count, ValueObject)

    def test_negative_value_raises(self):
        with pytest.raises(ValueError):
            AttemptCount(value=-1)


class TestChannel:
    def test_has_email(self):
        assert Channel.EMAIL == "email"

    def test_has_sms(self):
        assert Channel.SMS == "sms"


class TestContentSensitivity:
    def test_has_sensitive(self):
        assert ContentSensitivity.SENSITIVE == "sensitive"

    def test_has_standard(self):
        assert ContentSensitivity.STANDARD == "standard"


class TestDeliveryStatus:
    def test_has_pending(self):
        assert DeliveryStatus.PENDING == "pending"

    def test_has_sent(self):
        assert DeliveryStatus.SENT == "sent"

    def test_has_failed(self):
        assert DeliveryStatus.FAILED == "failed"

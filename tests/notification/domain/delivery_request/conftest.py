from uuid import uuid4

import pytest

from pydentity.notification.domain.delivery_request.aggregate import DeliveryRequest
from pydentity.notification.domain.delivery_request.aggregate_id import (
    DeliveryRequestId,
)
from pydentity.notification.domain.delivery_request.value_objects import (
    Channel,
    MessageContent,
    Recipient,
)
from pydentity.shared_kernel import AccountId


@pytest.fixture
def delivery_request_id() -> DeliveryRequestId:
    return DeliveryRequestId(value=uuid4())


@pytest.fixture
def recipient() -> Recipient:
    return Recipient(address="user@example.com")


@pytest.fixture
def message_content() -> MessageContent:
    return MessageContent(subject="Test Subject", body="Test body content")


@pytest.fixture
def pending_delivery(
    delivery_request_id: DeliveryRequestId,
    account_id: AccountId,
    recipient: Recipient,
    message_content: MessageContent,
) -> DeliveryRequest:
    return DeliveryRequest.create(
        delivery_request_id,
        account_id,
        recipient,
        Channel.EMAIL,
        message_content,
        is_sensitive=False,
    )


@pytest.fixture
def sensitive_pending_delivery(
    delivery_request_id: DeliveryRequestId,
    account_id: AccountId,
    recipient: Recipient,
    message_content: MessageContent,
) -> DeliveryRequest:
    return DeliveryRequest.create(
        delivery_request_id,
        account_id,
        recipient,
        Channel.EMAIL,
        message_content,
        is_sensitive=True,
    )

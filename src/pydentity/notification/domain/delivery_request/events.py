from dataclasses import dataclass

from pydentity.notification.domain.delivery_request.value_objects import (
    AttemptCount,
    Channel,
    DeliveryRequestId,
)
from pydentity.shared_kernel.building_blocks import DomainEvent
from pydentity.shared_kernel.value_objects import AccountId


@dataclass(frozen=True, slots=True)
class DeliveryRequestCreated(DomainEvent):
    delivery_request_id: DeliveryRequestId
    account_id: AccountId
    channel: Channel


@dataclass(frozen=True, slots=True)
class MessageDelivered(DomainEvent):
    delivery_request_id: DeliveryRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class DeliveryAttemptFailed(DomainEvent):
    delivery_request_id: DeliveryRequestId
    account_id: AccountId
    attempt_count: AttemptCount


@dataclass(frozen=True, slots=True)
class MessageDeliveryFailed(DomainEvent):
    delivery_request_id: DeliveryRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class ContentPurged(DomainEvent):
    delivery_request_id: DeliveryRequestId
    account_id: AccountId

from dataclasses import dataclass

from pydentity.notification.domain.delivery_request.aggregate_id import (
    DeliveryRequestId,
)
from pydentity.shared_kernel import AccountId, DomainEvent


@dataclass(frozen=True, slots=True)
class MessageDelivered(DomainEvent):
    request_id: DeliveryRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class MessageDeliveryFailed(DomainEvent):
    request_id: DeliveryRequestId
    account_id: AccountId

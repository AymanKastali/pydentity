from pydentity.notification.domain.delivery_request.value_objects import (
    ContentSensitivity,
    DeliveryStatus,
)
from pydentity.shared_kernel.building_blocks import DomainError


class DeliveryRequestError(DomainError):
    pass


class DeliveryRequestNotPendingError(DeliveryRequestError):
    def __init__(self, current_status: DeliveryStatus) -> None:
        super().__init__(
            f"Delivery request must be pending, but status is {current_status}."
        )


class ContentPurgeRequiresSentError(DeliveryRequestError):
    def __init__(self, current_status: DeliveryStatus) -> None:
        super().__init__(
            f"Content purge requires sent status, but status is {current_status}."
        )


class ContentPurgeRequiresSensitiveError(DeliveryRequestError):
    def __init__(self, current_sensitivity: ContentSensitivity) -> None:
        super().__init__(
            "Content purge requires sensitive content, "
            f"but sensitivity is {current_sensitivity}."
        )

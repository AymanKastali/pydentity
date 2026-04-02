from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.notification.domain.delivery_request.aggregate import (
        DeliveryRequest,
    )
    from pydentity.notification.domain.delivery_request.aggregate_id import (
        DeliveryRequestId,
    )


class DeliveryRequestRepository(ABC):
    @abstractmethod
    async def save(self, request: DeliveryRequest) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, request_id: DeliveryRequestId
    ) -> DeliveryRequest | None: ...

    @abstractmethod
    async def find_pending(self) -> list[DeliveryRequest]: ...

    @abstractmethod
    async def find_failed(self) -> list[DeliveryRequest]: ...

    @abstractmethod
    async def find_sensitive_requiring_purge(self) -> list[DeliveryRequest]: ...

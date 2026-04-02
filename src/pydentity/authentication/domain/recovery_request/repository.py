from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.authentication.domain.recovery_request.aggregate import (
        RecoveryRequest,
    )
    from pydentity.authentication.domain.recovery_request.aggregate_id import (
        RecoveryRequestId,
    )
    from pydentity.shared_kernel import AccountId


class RecoveryRequestRepository(ABC):
    @abstractmethod
    async def save(self, request: RecoveryRequest) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, request_id: RecoveryRequestId
    ) -> RecoveryRequest | None: ...

    @abstractmethod
    async def find_active_by_account_id(
        self, account_id: AccountId
    ) -> RecoveryRequest | None: ...

    @abstractmethod
    async def find_by_token_hash(self, token_hash: str) -> RecoveryRequest | None: ...

    @abstractmethod
    async def delete_expired(self) -> None: ...

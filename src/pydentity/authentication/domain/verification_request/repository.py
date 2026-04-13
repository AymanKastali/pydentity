from abc import ABC, abstractmethod

from pydentity.authentication.domain.verification_request.aggregate import (
    VerificationRequest,
)
from pydentity.authentication.domain.verification_request.value_objects import (
    VerificationRequestId,
    VerificationRequestType,
)
from pydentity.shared_kernel.value_objects import AccountId


class VerificationRequestRepository(ABC):
    @abstractmethod
    async def save(self, verification_request: VerificationRequest) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, verification_request_id: VerificationRequestId
    ) -> VerificationRequest | None: ...

    @abstractmethod
    async def find_pending_by_account_id(
        self, account_id: AccountId
    ) -> list[VerificationRequest]: ...

    @abstractmethod
    async def find_pending_by_account_id_and_type(
        self, account_id: AccountId, request_type: VerificationRequestType
    ) -> VerificationRequest | None: ...

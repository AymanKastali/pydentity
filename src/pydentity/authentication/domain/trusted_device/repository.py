from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.authentication.domain.trusted_device.aggregate import TrustedDevice
    from pydentity.authentication.domain.trusted_device.aggregate_id import (
        TrustedDeviceId,
    )
    from pydentity.authentication.domain.trusted_device.value_objects import (
        DeviceFingerprint,
    )
    from pydentity.shared_kernel import AccountId


class TrustedDeviceRepository(ABC):
    @abstractmethod
    async def save(self, device: TrustedDevice) -> None: ...

    @abstractmethod
    async def find_by_id(self, device_id: TrustedDeviceId) -> TrustedDevice | None: ...

    @abstractmethod
    async def find_by_account_and_fingerprint(
        self, account_id: AccountId, fingerprint: DeviceFingerprint
    ) -> TrustedDevice | None: ...

    @abstractmethod
    async def find_active_by_account_id(
        self, account_id: AccountId
    ) -> list[TrustedDevice]: ...

    @abstractmethod
    async def count_active_by_account_id(self, account_id: AccountId) -> int: ...

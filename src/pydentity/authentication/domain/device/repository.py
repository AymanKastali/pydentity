from abc import ABC, abstractmethod

from pydentity.authentication.domain.device.aggregate import Device
from pydentity.authentication.domain.device.value_objects import (
    HashedDeviceFingerprint,
)
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


class DeviceRepository(ABC):
    @abstractmethod
    async def save(self, device: Device) -> None: ...

    @abstractmethod
    async def find_by_id(self, device_id: DeviceId) -> Device | None: ...

    @abstractmethod
    async def find_by_fingerprint(
        self, fingerprint: HashedDeviceFingerprint
    ) -> Device | None: ...

    @abstractmethod
    async def find_by_account_id(self, account_id: AccountId) -> list[Device]: ...

    @abstractmethod
    async def count_active_by_account_id(self, account_id: AccountId) -> int: ...

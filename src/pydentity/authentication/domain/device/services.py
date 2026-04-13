from pydentity.authentication.domain.device.aggregate import Device
from pydentity.authentication.domain.device.errors import MaxDevicesReachedError
from pydentity.authentication.domain.device.interfaces import DeviceFingerprintHasher
from pydentity.authentication.domain.device.repository import DeviceRepository
from pydentity.authentication.domain.device.value_objects import (
    DevicePolicy,
    DeviceRevocationReason,
    DeviceStatus,
    RawDeviceFingerprint,
)
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


class RegisterDevice:
    def __init__(
        self, hasher: DeviceFingerprintHasher, repository: DeviceRepository
    ) -> None:
        self._hasher = hasher
        self._repository = repository

    async def register(
        self,
        device_id: DeviceId,
        account_id: AccountId,
        fingerprint: RawDeviceFingerprint,
        policy: DevicePolicy,
    ) -> Device:
        await self._guard_within_device_limit(account_id, policy)
        hashed = self._hasher.hash(fingerprint)
        return Device.create(
            device_id=device_id, account_id=account_id, fingerprint=hashed
        )

    async def _guard_within_device_limit(
        self, account_id: AccountId, policy: DevicePolicy
    ) -> None:
        active_count = await self._repository.count_active_by_account_id(account_id)
        if active_count >= policy.max_devices_per_account:
            raise MaxDevicesReachedError(policy.max_devices_per_account)


class RevokeDevices:
    def __init__(self, repository: DeviceRepository) -> None:
        self._repository = repository

    async def revoke_active_devices(
        self, account_id: AccountId, reason: DeviceRevocationReason
    ) -> None:
        devices = await self._repository.find_by_account_id(account_id)
        for device in devices:
            if device.status is DeviceStatus.ACTIVE:
                device.revoke(reason)

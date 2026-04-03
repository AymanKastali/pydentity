import pytest

from pydentity.authentication.domain.trusted_device.aggregate import TrustedDevice
from pydentity.authentication.domain.trusted_device.aggregate_id import TrustedDeviceId
from pydentity.authentication.domain.trusted_device.errors import (
    DeviceLimitExceededError,
)
from pydentity.authentication.domain.trusted_device.repository import (
    TrustedDeviceRepository,
)
from pydentity.authentication.domain.trusted_device.services import EnforceDeviceLimit
from pydentity.authentication.domain.trusted_device.value_objects import (
    DeviceFingerprint,
    DevicePolicy,
)
from pydentity.shared_kernel import AccountId

# --- Fake repository ---


class FakeTrustedDeviceRepository(TrustedDeviceRepository):
    def __init__(self, active_count: int = 0) -> None:
        self._active_count = active_count

    async def save(self, device: TrustedDevice) -> None:
        pass

    async def find_by_id(self, device_id: TrustedDeviceId) -> TrustedDevice | None:
        return None

    async def find_by_account_and_fingerprint(
        self, account_id: AccountId, fingerprint: DeviceFingerprint
    ) -> TrustedDevice | None:
        return None

    async def find_active_by_account_id(
        self, account_id: AccountId
    ) -> list[TrustedDevice]:
        return []

    async def count_active_by_account_id(self, account_id: AccountId) -> int:
        return self._active_count


# --- EnforceDeviceLimit ---


class TestEnforceDeviceLimit:
    async def test_passes_when_under_limit(self, account_id: AccountId):
        repository = FakeTrustedDeviceRepository(active_count=3)
        policy = DevicePolicy(max_devices=5)
        await EnforceDeviceLimit.check(account_id, repository, policy)

    async def test_raises_when_at_limit(self, account_id: AccountId):
        repository = FakeTrustedDeviceRepository(active_count=5)
        policy = DevicePolicy(max_devices=5)
        with pytest.raises(DeviceLimitExceededError):
            await EnforceDeviceLimit.check(account_id, repository, policy)

    async def test_raises_when_over_limit(self, account_id: AccountId):
        repository = FakeTrustedDeviceRepository(active_count=6)
        policy = DevicePolicy(max_devices=5)
        with pytest.raises(DeviceLimitExceededError):
            await EnforceDeviceLimit.check(account_id, repository, policy)

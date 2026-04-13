from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from pydentity.authentication.domain.device.aggregate import Device
from pydentity.authentication.domain.device.errors import MaxDevicesReachedError
from pydentity.authentication.domain.device.interfaces import DeviceFingerprintHasher
from pydentity.authentication.domain.device.repository import DeviceRepository
from pydentity.authentication.domain.device.services import (
    RegisterDevice,
    RevokeDevices,
)
from pydentity.authentication.domain.device.value_objects import (
    DevicePolicy,
    DeviceRevocationReason,
    DeviceStatus,
    HashedDeviceFingerprint,
    RawDeviceFingerprint,
)
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


def _make_hasher(hashed_value: str = "hashed-fp") -> DeviceFingerprintHasher:
    hasher = AsyncMock(spec=DeviceFingerprintHasher)
    hasher.hash.return_value = HashedDeviceFingerprint(value=hashed_value)
    return hasher


def _make_repository(active_count: int = 0) -> DeviceRepository:
    repo = AsyncMock(spec=DeviceRepository)
    repo.count_active_by_account_id.return_value = active_count
    return repo


class TestRegisterDevice:
    @pytest.mark.asyncio
    async def test_creates_active_device(self):
        service = RegisterDevice(
            hasher=_make_hasher(), repository=_make_repository(active_count=0)
        )
        device = await service.register(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            fingerprint=RawDeviceFingerprint(value="raw-fp"),
            policy=DevicePolicy(max_devices_per_account=5),
        )
        assert device.status == DeviceStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_hashes_fingerprint(self):
        hasher = _make_hasher(hashed_value="hashed-abc")
        service = RegisterDevice(
            hasher=hasher, repository=_make_repository(active_count=0)
        )
        device = await service.register(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            fingerprint=RawDeviceFingerprint(value="raw-fp"),
            policy=DevicePolicy(max_devices_per_account=5),
        )
        assert device.fingerprint == HashedDeviceFingerprint(value="hashed-abc")

    @pytest.mark.asyncio
    async def test_raises_when_max_devices_reached(self):
        service = RegisterDevice(
            hasher=_make_hasher(), repository=_make_repository(active_count=3)
        )
        with pytest.raises(MaxDevicesReachedError):
            await service.register(
                device_id=DeviceId(value=uuid4()),
                account_id=AccountId(value=uuid4()),
                fingerprint=RawDeviceFingerprint(value="raw-fp"),
                policy=DevicePolicy(max_devices_per_account=3),
            )

    @pytest.mark.asyncio
    async def test_raises_when_over_max_devices(self):
        service = RegisterDevice(
            hasher=_make_hasher(), repository=_make_repository(active_count=5)
        )
        with pytest.raises(MaxDevicesReachedError):
            await service.register(
                device_id=DeviceId(value=uuid4()),
                account_id=AccountId(value=uuid4()),
                fingerprint=RawDeviceFingerprint(value="raw-fp"),
                policy=DevicePolicy(max_devices_per_account=3),
            )


def _make_device_repository(devices: list[Device]) -> DeviceRepository:
    repo = AsyncMock(spec=DeviceRepository)
    repo.find_by_account_id.return_value = devices
    return repo


class TestRevokeDevices:
    @pytest.mark.asyncio
    async def test_revokes_all_active_devices(self):
        aid = AccountId(value=uuid4())
        d1 = Device.create(
            device_id=DeviceId(value=uuid4()),
            account_id=aid,
            fingerprint=HashedDeviceFingerprint(value="fp1"),
        )
        d2 = Device.create(
            device_id=DeviceId(value=uuid4()),
            account_id=aid,
            fingerprint=HashedDeviceFingerprint(value="fp2"),
        )

        service = RevokeDevices(repository=_make_device_repository([d1, d2]))
        await service.revoke_active_devices(aid, DeviceRevocationReason.CLOSURE)

        assert d1.status == DeviceStatus.REVOKED
        assert d2.status == DeviceStatus.REVOKED

    @pytest.mark.asyncio
    async def test_skips_already_revoked_devices(self):
        aid = AccountId(value=uuid4())
        active = Device.create(
            device_id=DeviceId(value=uuid4()),
            account_id=aid,
            fingerprint=HashedDeviceFingerprint(value="fp1"),
        )
        revoked = Device.create(
            device_id=DeviceId(value=uuid4()),
            account_id=aid,
            fingerprint=HashedDeviceFingerprint(value="fp2"),
        )
        revoked.revoke(DeviceRevocationReason.MANUAL)

        service = RevokeDevices(repository=_make_device_repository([active, revoked]))
        await service.revoke_active_devices(aid, DeviceRevocationReason.CLOSURE)

        assert active.status == DeviceStatus.REVOKED
        assert revoked.status == DeviceStatus.REVOKED

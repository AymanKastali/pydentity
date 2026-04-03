from datetime import datetime
from uuid import uuid4

import pytest

from pydentity.authentication.domain.trusted_device.aggregate import TrustedDevice
from pydentity.authentication.domain.trusted_device.aggregate_id import TrustedDeviceId
from pydentity.authentication.domain.trusted_device.value_objects import (
    DeviceFingerprint,
    DevicePolicy,
)
from pydentity.shared_kernel import AccountId


@pytest.fixture
def device_id() -> TrustedDeviceId:
    return TrustedDeviceId(value=uuid4())


@pytest.fixture
def fingerprint() -> DeviceFingerprint:
    return DeviceFingerprint(value="browser-fingerprint-sha256-abc123")


@pytest.fixture
def device_policy() -> DevicePolicy:
    return DevicePolicy(max_devices=5)


@pytest.fixture
def registered_device(
    device_id: TrustedDeviceId,
    account_id: AccountId,
    fingerprint: DeviceFingerprint,
    now: datetime,
    far_future: datetime,
) -> TrustedDevice:
    device = TrustedDevice.register(device_id, account_id, fingerprint, now, far_future)
    device.clear_events()
    return device

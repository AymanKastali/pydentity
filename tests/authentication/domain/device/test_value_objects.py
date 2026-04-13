from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.authentication.domain.device.value_objects import (
    DevicePolicy,
    DeviceRevocationReason,
    DeviceStatus,
    HashedDeviceFingerprint,
    RawDeviceFingerprint,
)
from pydentity.shared_kernel.building_blocks import ValueObject


class TestDeviceStatus:
    def test_has_active(self):
        assert DeviceStatus.ACTIVE == "active"

    def test_has_revoked(self):
        assert DeviceStatus.REVOKED == "revoked"


class TestDeviceRevocationReason:
    def test_has_manual(self):
        assert DeviceRevocationReason.MANUAL == "manual"

    def test_has_admin(self):
        assert DeviceRevocationReason.ADMIN == "admin"

    def test_has_lockout(self):
        assert DeviceRevocationReason.LOCKOUT == "lockout"

    def test_has_closure(self):
        assert DeviceRevocationReason.CLOSURE == "closure"


class TestRawDeviceFingerprint:
    def test_stores_value(self):
        fp = RawDeviceFingerprint(value="abc123")
        assert fp.value == "abc123"

    def test_frozen(self):
        fp = RawDeviceFingerprint(value="abc123")
        with pytest.raises(FrozenInstanceError):
            fp.value = "other"  # type: ignore[misc]

    def test_equal_by_value(self):
        assert RawDeviceFingerprint(value="x") == RawDeviceFingerprint(value="x")

    def test_is_value_object(self):
        assert isinstance(RawDeviceFingerprint(value="x"), ValueObject)

    def test_blank_raises(self):
        with pytest.raises(ValueError):
            RawDeviceFingerprint(value="   ")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            RawDeviceFingerprint(value="")


class TestHashedDeviceFingerprint:
    def test_stores_value(self):
        fp = HashedDeviceFingerprint(value="hashed123")
        assert fp.value == "hashed123"

    def test_frozen(self):
        fp = HashedDeviceFingerprint(value="hashed123")
        with pytest.raises(FrozenInstanceError):
            fp.value = "other"  # type: ignore[misc]

    def test_equal_by_value(self):
        assert HashedDeviceFingerprint(value="h") == HashedDeviceFingerprint(value="h")

    def test_is_value_object(self):
        assert isinstance(HashedDeviceFingerprint(value="h"), ValueObject)

    def test_blank_raises(self):
        with pytest.raises(ValueError):
            HashedDeviceFingerprint(value="   ")


class TestDevicePolicy:
    def test_stores_value(self):
        policy = DevicePolicy(max_devices_per_account=5)
        assert policy.max_devices_per_account == 5

    def test_frozen(self):
        policy = DevicePolicy(max_devices_per_account=5)
        with pytest.raises(FrozenInstanceError):
            policy.max_devices_per_account = 10  # type: ignore[misc]

    def test_equal_by_value(self):
        assert DevicePolicy(max_devices_per_account=3) == DevicePolicy(
            max_devices_per_account=3
        )

    def test_is_value_object(self):
        assert isinstance(DevicePolicy(max_devices_per_account=1), ValueObject)

    def test_zero_raises(self):
        with pytest.raises(ValueError):
            DevicePolicy(max_devices_per_account=0)

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            DevicePolicy(max_devices_per_account=-1)

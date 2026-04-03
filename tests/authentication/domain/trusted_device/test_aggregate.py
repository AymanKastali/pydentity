from datetime import datetime, timedelta

import pytest

from pydentity.authentication.domain.trusted_device.aggregate import TrustedDevice
from pydentity.authentication.domain.trusted_device.aggregate_id import TrustedDeviceId
from pydentity.authentication.domain.trusted_device.errors import (
    DeviceAlreadyExpiredError,
    DeviceAlreadyRevokedError,
)
from pydentity.authentication.domain.trusted_device.events import (
    DeviceTrusted,
    TrustedDeviceExpired,
    TrustedDeviceRevoked,
)
from pydentity.authentication.domain.trusted_device.value_objects import (
    DeviceFingerprint,
    DeviceRevocationReason,
    TrustedDeviceStatus,
)
from pydentity.shared_kernel import AccountId

# --- Factory ---


class TestTrustedDeviceRegister:
    def test_creates_registered_device(
        self,
        device_id: TrustedDeviceId,
        account_id: AccountId,
        fingerprint: DeviceFingerprint,
        now: datetime,
        far_future: datetime,
    ):
        device = TrustedDevice.register(
            device_id, account_id, fingerprint, now, far_future
        )
        assert device.status == TrustedDeviceStatus.REGISTERED

    def test_records_device_trusted_event(
        self,
        device_id: TrustedDeviceId,
        account_id: AccountId,
        fingerprint: DeviceFingerprint,
        now: datetime,
        far_future: datetime,
    ):
        device = TrustedDevice.register(
            device_id, account_id, fingerprint, now, far_future
        )
        assert len(device.events) == 1
        assert isinstance(device.events[0], DeviceTrusted)

    def test_stores_fingerprint(
        self,
        device_id: TrustedDeviceId,
        account_id: AccountId,
        fingerprint: DeviceFingerprint,
        now: datetime,
        far_future: datetime,
    ):
        device = TrustedDevice.register(
            device_id, account_id, fingerprint, now, far_future
        )
        assert device.fingerprint == fingerprint

    def test_stores_expires_at(
        self,
        device_id: TrustedDeviceId,
        account_id: AccountId,
        fingerprint: DeviceFingerprint,
        now: datetime,
        far_future: datetime,
    ):
        device = TrustedDevice.register(
            device_id, account_id, fingerprint, now, far_future
        )
        assert device.expires_at == far_future


# --- Queries ---


class TestTrustedDeviceIsTrusted:
    def test_true_when_registered_and_not_expired(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        assert registered_device.is_trusted(now) is True

    def test_false_when_time_past_expiry(
        self,
        registered_device: TrustedDevice,
        far_future: datetime,
    ):
        after_expiry = far_future + timedelta(days=1)
        assert registered_device.is_trusted(after_expiry) is False

    def test_false_when_revoked(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.revoke(DeviceRevocationReason.MANUAL, now)
        assert registered_device.is_trusted(now) is False


# --- Revoke ---


class TestTrustedDeviceRevoke:
    def test_transitions_to_revoked(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.revoke(DeviceRevocationReason.MANUAL, now)
        assert registered_device.status == TrustedDeviceStatus.REVOKED

    def test_records_trusted_device_revoked_event(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.revoke(DeviceRevocationReason.ADMIN, now)
        assert isinstance(registered_device.events[0], TrustedDeviceRevoked)
        assert registered_device.events[0].reason == DeviceRevocationReason.ADMIN

    def test_raises_when_already_revoked(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.revoke(DeviceRevocationReason.MANUAL, now)
        with pytest.raises(DeviceAlreadyRevokedError):
            registered_device.revoke(DeviceRevocationReason.MANUAL, now)

    def test_raises_when_already_expired(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.expire(now)
        with pytest.raises(DeviceAlreadyExpiredError):
            registered_device.revoke(DeviceRevocationReason.MANUAL, now)


# --- Expire ---


class TestTrustedDeviceExpire:
    def test_transitions_to_expired(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.expire(now)
        assert registered_device.status == TrustedDeviceStatus.EXPIRED

    def test_records_trusted_device_expired_event(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.expire(now)
        assert isinstance(registered_device.events[0], TrustedDeviceExpired)

    def test_raises_when_already_revoked(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.revoke(DeviceRevocationReason.MANUAL, now)
        with pytest.raises(DeviceAlreadyRevokedError):
            registered_device.expire(now)

    def test_raises_when_already_expired(
        self,
        registered_device: TrustedDevice,
        now: datetime,
    ):
        registered_device.expire(now)
        with pytest.raises(DeviceAlreadyExpiredError):
            registered_device.expire(now)

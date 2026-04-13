from uuid import uuid4

import pytest

from pydentity.authentication.domain.device.aggregate import Device
from pydentity.authentication.domain.device.errors import DeviceNotActiveError
from pydentity.authentication.domain.device.events import (
    DeviceRegistered,
    DeviceRevoked,
)
from pydentity.authentication.domain.device.value_objects import (
    DeviceRevocationReason,
    DeviceStatus,
    HashedDeviceFingerprint,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


def _make_device() -> Device:
    return Device.create(
        device_id=DeviceId(value=uuid4()),
        account_id=AccountId(value=uuid4()),
        fingerprint=HashedDeviceFingerprint(value="hashed-fp"),
    )


class TestDeviceCreate:
    def test_create_returns_active_status(self):
        device = _make_device()
        assert device.status == DeviceStatus.ACTIVE

    def test_create_returns_correct_fields(self):
        did = DeviceId(value=uuid4())
        aid = AccountId(value=uuid4())
        fp = HashedDeviceFingerprint(value="fp123")
        device = Device.create(device_id=did, account_id=aid, fingerprint=fp)
        assert device.id == did
        assert device.account_id == aid
        assert device.fingerprint == fp

    def test_create_records_device_registered_event(self):
        device = _make_device()
        events = device.events
        assert len(events) == 1
        assert isinstance(events[0], DeviceRegistered)


class TestDeviceAggregate:
    def test_is_aggregate_root(self):
        device = _make_device()
        assert isinstance(device, AggregateRoot)

    def test_identity_equality(self):
        uid = uuid4()
        did = DeviceId(value=uid)
        a = Device.create(
            device_id=did,
            account_id=AccountId(value=uuid4()),
            fingerprint=HashedDeviceFingerprint(value="a"),
        )
        b = Device.create(
            device_id=did,
            account_id=AccountId(value=uuid4()),
            fingerprint=HashedDeviceFingerprint(value="b"),
        )
        assert a == b

    def test_different_id_not_equal(self):
        a = _make_device()
        b = _make_device()
        assert a != b


class TestRevoke:
    def test_transitions_to_revoked(self):
        device = _make_device()
        device.revoke(DeviceRevocationReason.MANUAL)
        assert device.status == DeviceStatus.REVOKED

    def test_records_device_revoked_event(self):
        device = _make_device()
        device.clear_events()
        device.revoke(DeviceRevocationReason.ADMIN)
        events = device.events
        assert len(events) == 1
        assert isinstance(events[0], DeviceRevoked)

    def test_revoked_event_carries_reason(self):
        device = _make_device()
        device.clear_events()
        device.revoke(DeviceRevocationReason.LOCKOUT)
        event = device.events[0]
        assert isinstance(event, DeviceRevoked)
        assert event.reason == DeviceRevocationReason.LOCKOUT

    def test_from_revoked_raises(self):
        device = _make_device()
        device.revoke(DeviceRevocationReason.MANUAL)
        with pytest.raises(DeviceNotActiveError):
            device.revoke(DeviceRevocationReason.ADMIN)

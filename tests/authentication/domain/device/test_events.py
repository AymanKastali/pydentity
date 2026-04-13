from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.authentication.domain.device.events import (
    DeviceRegistered,
    DeviceRevoked,
)
from pydentity.authentication.domain.device.value_objects import (
    DeviceRevocationReason,
)
from pydentity.shared_kernel.building_blocks import DomainEvent, EventName
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


class TestDeviceRegistered:
    def test_creation_with_correct_fields(self):
        did = DeviceId(value=uuid4())
        aid = AccountId(value=uuid4())
        event = DeviceRegistered(device_id=did, account_id=aid)
        assert event.device_id == did
        assert event.account_id == aid

    def test_frozen(self):
        event = DeviceRegistered(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        with pytest.raises(FrozenInstanceError):
            event.device_id = DeviceId(value=uuid4())  # type: ignore[misc]

    def test_is_domain_event(self):
        event = DeviceRegistered(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = DeviceRegistered(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
        )
        assert event.name == EventName("DeviceRegistered")


class TestDeviceRevoked:
    def test_creation_with_correct_fields(self):
        did = DeviceId(value=uuid4())
        aid = AccountId(value=uuid4())
        reason = DeviceRevocationReason.MANUAL
        event = DeviceRevoked(device_id=did, account_id=aid, reason=reason)
        assert event.device_id == did
        assert event.account_id == aid
        assert event.reason == reason

    def test_frozen(self):
        event = DeviceRevoked(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            reason=DeviceRevocationReason.ADMIN,
        )
        with pytest.raises(FrozenInstanceError):
            event.reason = DeviceRevocationReason.MANUAL  # type: ignore[misc]

    def test_is_domain_event(self):
        event = DeviceRevoked(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            reason=DeviceRevocationReason.LOCKOUT,
        )
        assert isinstance(event, DomainEvent)

    def test_has_correct_event_name(self):
        event = DeviceRevoked(
            device_id=DeviceId(value=uuid4()),
            account_id=AccountId(value=uuid4()),
            reason=DeviceRevocationReason.CLOSURE,
        )
        assert event.name == EventName("DeviceRevoked")

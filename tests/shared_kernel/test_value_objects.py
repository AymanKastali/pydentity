from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.shared_kernel.value_objects import AccountId, DeviceId


class TestAccountId:
    def test_stores_uuid(self):
        uid = uuid4()
        account_id = AccountId(value=uid)
        assert account_id.value == uid

    def test_frozen(self):
        account_id = AccountId(value=uuid4())
        with pytest.raises(FrozenInstanceError):
            account_id.value = uuid4()  # type: ignore[misc]

    def test_equal_by_value(self):
        uid = uuid4()
        assert AccountId(value=uid) == AccountId(value=uid)

    def test_not_equal_different_value(self):
        assert AccountId(value=uuid4()) != AccountId(value=uuid4())

    def test_not_equal_to_device_id(self):
        uid = uuid4()
        assert AccountId(value=uid) != DeviceId(value=uid)


class TestDeviceId:
    def test_stores_uuid(self):
        uid = uuid4()
        device_id = DeviceId(value=uid)
        assert device_id.value == uid

    def test_frozen(self):
        device_id = DeviceId(value=uuid4())
        with pytest.raises(FrozenInstanceError):
            device_id.value = uuid4()  # type: ignore[misc]

    def test_equal_by_value(self):
        uid = uuid4()
        assert DeviceId(value=uid) == DeviceId(value=uid)

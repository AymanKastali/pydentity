from typing import Self

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


class Device(AggregateRoot[DeviceId]):
    def __init__(
        self,
        device_id: DeviceId,
        account_id: AccountId,
        fingerprint: HashedDeviceFingerprint,
        status: DeviceStatus,
    ) -> None:
        super().__init__(device_id)
        self._account_id: AccountId = account_id
        self._fingerprint: HashedDeviceFingerprint = fingerprint
        self._status: DeviceStatus = status

    @classmethod
    def create(
        cls,
        device_id: DeviceId,
        account_id: AccountId,
        fingerprint: HashedDeviceFingerprint,
    ) -> Self:
        device = cls(
            device_id=device_id,
            account_id=account_id,
            fingerprint=fingerprint,
            status=DeviceStatus.ACTIVE,
        )
        device._record_device_registered()
        return device

    def _record_device_registered(self) -> None:
        self.record_event(
            DeviceRegistered(device_id=self._id, account_id=self._account_id)
        )

    def revoke(self, reason: DeviceRevocationReason) -> None:
        self._guard_status_is_active()
        self._mark_as_revoked()
        self._record_device_revoked(reason)

    def _guard_status_is_active(self) -> None:
        if self._status is not DeviceStatus.ACTIVE:
            raise DeviceNotActiveError(self._status)

    def _mark_as_revoked(self) -> None:
        self._status = DeviceStatus.REVOKED

    def _record_device_revoked(self, reason: DeviceRevocationReason) -> None:
        self.record_event(
            DeviceRevoked(
                device_id=self._id, account_id=self._account_id, reason=reason
            )
        )

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def fingerprint(self) -> HashedDeviceFingerprint:
        return self._fingerprint

    @property
    def status(self) -> DeviceStatus:
        return self._status

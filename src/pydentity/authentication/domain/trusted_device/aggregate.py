from typing import TYPE_CHECKING

from pydentity.authentication.domain.trusted_device.aggregate_id import TrustedDeviceId
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
from pydentity.shared_kernel import AggregateRoot

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.shared_kernel import AccountId


class TrustedDevice(AggregateRoot[TrustedDeviceId]):
    def __init__(
        self,
        device_id: TrustedDeviceId,
        account_id: AccountId,
        fingerprint: DeviceFingerprint,
        status: TrustedDeviceStatus,
        expires_at: datetime,
    ) -> None:
        super().__init__(device_id)
        self._account_id: AccountId = account_id
        self._fingerprint: DeviceFingerprint = fingerprint
        self._status: TrustedDeviceStatus = status
        self._expires_at: datetime = expires_at

    # --- Creation ---

    @classmethod
    def register(
        cls,
        device_id: TrustedDeviceId,
        account_id: AccountId,
        fingerprint: DeviceFingerprint,
        now: datetime,
        expires_at: datetime,
    ) -> TrustedDevice:
        device = cls(
            device_id=device_id,
            account_id=account_id,
            fingerprint=fingerprint,
            status=TrustedDeviceStatus.REGISTERED,
            expires_at=expires_at,
        )
        device.record_event(
            DeviceTrusted(
                occurred_at=now,
                device_id=device_id,
                account_id=account_id,
                fingerprint=fingerprint,
            )
        )
        return device

    # --- Queries ---

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def fingerprint(self) -> DeviceFingerprint:
        return self._fingerprint

    @property
    def status(self) -> TrustedDeviceStatus:
        return self._status

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    def is_trusted(self, now: datetime) -> bool:
        return self._status.is_registered and not self._is_expired(now)

    def _is_expired(self, now: datetime) -> bool:
        return now >= self._expires_at

    # --- Revocation ---

    def revoke(self, reason: DeviceRevocationReason, now: datetime) -> None:
        self._status.guard_not_revoked()
        self._status.guard_not_expired()
        self._mark_revoked()
        self.record_event(
            TrustedDeviceRevoked(
                occurred_at=now,
                device_id=self._id,
                account_id=self._account_id,
                fingerprint=self._fingerprint,
                reason=reason,
            )
        )

    def _mark_revoked(self) -> None:
        self._status = TrustedDeviceStatus.REVOKED

    # --- Expiration ---

    def expire(self, now: datetime) -> None:
        self._status.guard_not_revoked()
        self._status.guard_not_expired()
        self._mark_expired()
        self.record_event(
            TrustedDeviceExpired(
                occurred_at=now,
                device_id=self._id,
                account_id=self._account_id,
                fingerprint=self._fingerprint,
            )
        )

    def _mark_expired(self) -> None:
        self._status = TrustedDeviceStatus.EXPIRED

from dataclasses import dataclass

from pydentity.authentication.domain.trusted_device.aggregate_id import TrustedDeviceId
from pydentity.authentication.domain.trusted_device.value_objects import (
    DeviceFingerprint,
    DeviceRevocationReason,
)
from pydentity.shared_kernel import AccountId, DomainEvent


@dataclass(frozen=True, slots=True)
class DeviceTrusted(DomainEvent):
    device_id: TrustedDeviceId
    account_id: AccountId
    fingerprint: DeviceFingerprint


@dataclass(frozen=True, slots=True)
class TrustedDeviceRevoked(DomainEvent):
    device_id: TrustedDeviceId
    account_id: AccountId
    fingerprint: DeviceFingerprint
    reason: DeviceRevocationReason


@dataclass(frozen=True, slots=True)
class TrustedDeviceExpired(DomainEvent):
    device_id: TrustedDeviceId
    account_id: AccountId
    fingerprint: DeviceFingerprint

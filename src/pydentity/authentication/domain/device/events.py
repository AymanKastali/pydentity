from dataclasses import dataclass

from pydentity.authentication.domain.device.value_objects import DeviceRevocationReason
from pydentity.shared_kernel.building_blocks import DomainEvent
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


@dataclass(frozen=True, slots=True)
class DeviceRegistered(DomainEvent):
    device_id: DeviceId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class DeviceRevoked(DomainEvent):
    device_id: DeviceId
    account_id: AccountId
    reason: DeviceRevocationReason

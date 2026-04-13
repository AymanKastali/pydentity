from dataclasses import dataclass

from pydentity.authentication.domain.session.value_objects import (
    SessionId,
    SessionRevocationReason,
)
from pydentity.shared_kernel.building_blocks import DomainEvent
from pydentity.shared_kernel.value_objects import AccountId, DeviceId


@dataclass(frozen=True, slots=True)
class SessionStarted(DomainEvent):
    session_id: SessionId
    account_id: AccountId
    device_id: DeviceId


@dataclass(frozen=True, slots=True)
class SessionRevoked(DomainEvent):
    session_id: SessionId
    account_id: AccountId
    device_id: DeviceId
    reason: SessionRevocationReason


@dataclass(frozen=True, slots=True)
class SessionRefreshed(DomainEvent):
    session_id: SessionId
    account_id: AccountId
    device_id: DeviceId

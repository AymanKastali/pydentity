from __future__ import annotations

from dataclasses import dataclass

from pydentity.domain.events.base import DomainEvent


@dataclass(frozen=True)
class DeviceRegistered(DomainEvent):
    device_id: str
    user_id: str
    device_name: str


@dataclass(frozen=True)
class DeviceTrusted(DomainEvent):
    device_id: str
    user_id: str


@dataclass(frozen=True)
class DeviceUntrusted(DomainEvent):
    device_id: str
    user_id: str


@dataclass(frozen=True)
class DeviceRevoked(DomainEvent):
    device_id: str
    user_id: str


@dataclass(frozen=True)
class DeviceLastActiveBumped(DomainEvent):
    device_id: str
    user_id: str

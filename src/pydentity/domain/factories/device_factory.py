from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.device import Device
from pydentity.domain.models.value_objects import DeviceFingerprint

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.value_objects import DeviceId, DeviceName, UserId


class DeviceFactory:
    def create(
        self,
        *,
        device_id: DeviceId,
        user_id: UserId,
        name: DeviceName,
        raw_fingerprint: str,
        platform: str,
        now: datetime,
        trusted: bool = False,
    ) -> Device:
        fingerprint = DeviceFingerprint.from_raw(raw_fingerprint)
        return Device.register(
            device_id=device_id,
            user_id=user_id,
            name=name,
            fingerprint=fingerprint,
            platform=platform,
            now=now,
            trusted=trusted,
        )

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import DeviceAlreadyRegisteredError
from pydentity.domain.models.device import Device
from pydentity.domain.models.value_objects import DeviceFingerprint

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.value_objects import DeviceId, DeviceName, UserId
    from pydentity.domain.ports.repositories import DeviceRepositoryPort


class RegisterDevice:
    def __init__(
        self,
        *,
        device_repo: DeviceRepositoryPort,
    ) -> None:
        self._repo = device_repo

    async def execute(
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

        if await self._repo.check_fingerprint_exists(user_id, fingerprint):
            raise DeviceAlreadyRegisteredError()

        return Device.create(
            device_id=device_id,
            user_id=user_id,
            name=name,
            fingerprint=fingerprint,
            platform=platform,
            now=now,
            trusted=trusted,
        )

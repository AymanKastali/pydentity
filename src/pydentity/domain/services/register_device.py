from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import DeviceAlreadyRegisteredError
from pydentity.domain.models.value_objects import DeviceFingerprint

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.factories.device_factory import DeviceFactory
    from pydentity.domain.models.device import Device
    from pydentity.domain.models.enums import DevicePlatform
    from pydentity.domain.models.value_objects import DeviceId, DeviceName, UserId
    from pydentity.domain.ports.repositories import DeviceRepositoryPort


class RegisterDevice:
    def __init__(
        self,
        *,
        device_repo: DeviceRepositoryPort,
        device_factory: DeviceFactory,
    ) -> None:
        self._repo = device_repo
        self._factory = device_factory

    async def execute(
        self,
        *,
        device_id: DeviceId,
        user_id: UserId,
        name: DeviceName,
        raw_fingerprint: str,
        platform: DevicePlatform,
        now: datetime,
        trusted: bool = False,
        email: str | None = None,
    ) -> Device:
        fingerprint = DeviceFingerprint.from_raw(raw_fingerprint)

        existing = await self._repo.find_by_fingerprint(user_id, fingerprint)
        if existing:
            raise DeviceAlreadyRegisteredError()

        return self._factory.create(
            device_id=device_id,
            user_id=user_id,
            name=name,
            raw_fingerprint=raw_fingerprint,
            platform=platform,
            now=now,
            trusted=trusted,
            email=email,
        )

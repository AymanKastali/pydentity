from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions.domain import (
    DeviceAlreadyRegisteredError,
    DeviceLimitExceededError,
)
from pydentity.domain.models.device import Device

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.value_objects import (
        DeviceFingerprint,
        DeviceName,
        DevicePolicy,
        UserId,
    )
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.repositories import DeviceRepositoryPort


class RegisterDevice:
    def __init__(
        self,
        *,
        device_repo: DeviceRepositoryPort,
        device_policy: DevicePolicy,
        identity_generator: IdentityGeneratorPort,
    ) -> None:
        self._repo = device_repo
        self._policy = device_policy
        self._identity_generator = identity_generator

    async def _ensure_device_not_registered(
        self, user_id: UserId, fingerprint: DeviceFingerprint
    ) -> None:
        existing = await self._repo.find_by_fingerprint(user_id, fingerprint)
        if existing is not None:
            raise DeviceAlreadyRegisteredError()

    async def _ensure_device_limit_not_exceeded(self, user_id: UserId) -> None:
        user_devices = await self._repo.find_all_for_user(user_id)
        if len(user_devices) >= self._policy.max_devices_per_user:
            raise DeviceLimitExceededError(
                max_devices=self._policy.max_devices_per_user,
            )

    async def execute(
        self,
        *,
        user_id: UserId,
        name: DeviceName,
        fingerprint: DeviceFingerprint,
        platform: str,
        now: datetime,
        trusted: bool = False,
    ) -> Device:
        await self._ensure_device_not_registered(user_id, fingerprint)
        await self._ensure_device_limit_not_exceeded(user_id)

        device_id = self._identity_generator.new_device_id()

        return Device.create(
            device_id=device_id,
            user_id=user_id,
            name=name,
            fingerprint=fingerprint,
            platform=platform,
            now=now,
            trusted=trusted,
        )

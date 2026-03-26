from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.events.device_events import (
    DeviceLastActiveBumped,
    DeviceMetadataUpdated,
    DeviceRegistered,
    DeviceRevoked,
    DeviceTrusted,
    DeviceUntrusted,
)
from pydentity.domain.exceptions.domain import (
    DeviceAlreadyRevokedError,
    DeviceAlreadyTrustedError,
    DeviceAlreadyUntrustedError,
    DeviceRevokedError,
)
from pydentity.domain.guards import verify_params
from pydentity.domain.models.base import AggregateRoot
from pydentity.domain.models.enums import DeviceStatus
from pydentity.domain.models.value_objects import (
    DeviceFingerprint,
    DeviceId,
    DeviceLastActive,
    DeviceName,
    UserId,
)

if TYPE_CHECKING:
    from datetime import datetime


class Device(AggregateRoot[DeviceId]):
    def __init__(
        self,
        *,
        device_id: DeviceId,
        user_id: UserId,
        name: DeviceName,
        fingerprint: DeviceFingerprint,
        platform: str,
        status: DeviceStatus,
        is_trusted: bool,
        last_active: DeviceLastActive,
    ) -> None:
        super().__init__()
        verify_params(
            device_id=(device_id, DeviceId),
            user_id=(user_id, UserId),
            name=(name, DeviceName),
            fingerprint=(fingerprint, DeviceFingerprint),
            platform=(platform, str),
            status=(status, DeviceStatus),
            is_trusted=(is_trusted, bool),
            last_active=(last_active, DeviceLastActive),
        )
        self._id = device_id
        self._user_id = user_id
        self._name = name
        self._fingerprint = fingerprint
        self._platform = platform
        self._status = status
        self._is_trusted = is_trusted
        self._last_active = last_active

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        device_id: DeviceId,
        user_id: UserId,
        name: DeviceName,
        fingerprint: DeviceFingerprint,
        platform: str,
        now: datetime,
        trusted: bool = False,
    ) -> Device:
        device = cls(
            device_id=device_id,
            user_id=user_id,
            name=name,
            fingerprint=fingerprint,
            platform=platform,
            status=DeviceStatus.ACTIVE,
            is_trusted=trusted,
            last_active=DeviceLastActive(last_active_at=now),
        )

        device._record_event(
            DeviceRegistered(
                device_id=str(device_id.value),
                user_id=str(user_id.value),
                device_name=name.value,
            )
        )
        return device

    @classmethod
    def _reconstitute(
        cls,
        device_id: DeviceId,
        user_id: UserId,
        name: DeviceName,
        fingerprint: DeviceFingerprint,
        platform: str,
        status: DeviceStatus,
        is_trusted: bool,
        last_active: DeviceLastActive,
    ) -> Device:
        return cls(
            device_id=device_id,
            user_id=user_id,
            name=name,
            fingerprint=fingerprint,
            platform=platform,
            status=status,
            is_trusted=is_trusted,
            last_active=last_active,
        )

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def user_id(self) -> UserId:
        return self._user_id

    @property
    def name(self) -> DeviceName:
        return self._name

    @property
    def fingerprint(self) -> DeviceFingerprint:
        return self._fingerprint

    @property
    def platform(self) -> str:
        return self._platform

    @property
    def status(self) -> DeviceStatus:
        return self._status

    @property
    def is_trusted(self) -> bool:
        return self._is_trusted

    @property
    def is_active(self) -> bool:
        return self._status == DeviceStatus.ACTIVE

    @property
    def last_active(self) -> DeviceLastActive:
        return self._last_active

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_active(self) -> None:
        if self._status == DeviceStatus.REVOKED:
            raise DeviceRevokedError()

    def _ensure_not_already_trusted(self) -> None:
        if self._is_trusted:
            raise DeviceAlreadyTrustedError()

    def _ensure_not_already_untrusted(self) -> None:
        if not self._is_trusted:
            raise DeviceAlreadyUntrustedError()

    def _ensure_not_already_revoked(self) -> None:
        if self._status == DeviceStatus.REVOKED:
            raise DeviceAlreadyRevokedError()

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def mark_active(self, now: datetime) -> None:
        self._ensure_active()

        self._last_active = self._last_active.bump(now)

        self._record_event(
            DeviceLastActiveBumped(
                device_id=str(self._id.value),
                user_id=str(self._user_id.value),
            )
        )

    def trust(self) -> None:
        self._ensure_active()
        self._ensure_not_already_trusted()

        self._is_trusted = True

        self._record_event(
            DeviceTrusted(
                device_id=str(self._id.value),
                user_id=str(self._user_id.value),
            )
        )

    def untrust(self) -> None:
        self._ensure_active()
        self._ensure_not_already_untrusted()

        self._is_trusted = False

        self._record_event(
            DeviceUntrusted(
                device_id=str(self._id.value),
                user_id=str(self._user_id.value),
            )
        )

    def revoke(self) -> None:
        self._ensure_not_already_revoked()

        self._status = DeviceStatus.REVOKED
        self._is_trusted = False

        self._record_event(
            DeviceRevoked(
                device_id=str(self._id.value),
                user_id=str(self._user_id.value),
                device_name=self._name.value,
            )
        )

    def update_metadata(self, *, name: DeviceName, platform: str) -> None:
        self._ensure_active()

        changed = self._name != name or self._platform != platform
        if not changed:
            return

        self._name = name
        self._platform = platform

        self._record_event(
            DeviceMetadataUpdated(
                device_id=str(self._id.value),
                user_id=str(self._user_id.value),
            )
        )

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.events.device_events import (
    DeviceLastActiveBumped,
    DeviceRegistered,
    DeviceRevoked,
    DeviceTrusted,
    DeviceUntrusted,
)
from pydentity.domain.exceptions.domain import (
    DeviceAlreadyRevokedError,
    DeviceAlreadyTrustedError,
    DeviceAlreadyUntrustedError,
    DeviceOwnershipError,
    DeviceRevokedError,
)
from pydentity.domain.models.base import AggregateRoot
from pydentity.domain.models.enums import DeviceStatus
from pydentity.domain.models.value_objects import (
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
        status: DeviceStatus,
        is_trusted: bool,
        last_active: DeviceLastActive,
    ) -> None:
        super().__init__()
        self._id = device_id
        self._user_id = user_id
        self._name = name
        self._status = status
        self._is_trusted = is_trusted
        self._last_active = last_active

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def register(
        cls,
        device_id: DeviceId,
        user_id: UserId,
        name: DeviceName,
        now: datetime,
        trusted: bool = False,
    ) -> Device:
        """
        Register a new device for a user.

        ``trusted=True`` can be passed when the caller has already
        completed a step-up MFA challenge for this device.
        """
        device = cls(
            device_id=device_id,
            user_id=user_id,
            name=name,
            status=DeviceStatus.ACTIVE,
            is_trusted=trusted,
            last_active=DeviceLastActive(last_active_at=now),
        )

        device._record_event(
            DeviceRegistered(
                device_id=device_id.value,
                user_id=user_id.value,
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
        status: DeviceStatus,
        is_trusted: bool,
        last_active: DeviceLastActive,
    ) -> Device:
        return cls(
            device_id=device_id,
            user_id=user_id,
            name=name,
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

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def mark_active(self, now: datetime) -> None:
        """
        Bump last-active timestamp on every successful token refresh.
        Silently ignores revoked devices — the session layer handles
        revocation; we never want a stale timestamp write to raise here.
        """
        if self._status == DeviceStatus.REVOKED:
            return

        self._last_active = self._last_active.bump(now)

        self._record_event(
            DeviceLastActiveBumped(
                device_id=self._id.value,
                user_id=self._user_id.value,
            )
        )

    def trust(self) -> None:
        """
        Mark device as trusted after a successful MFA step-up.
        Trusted devices may skip MFA on subsequent logins (policy
        enforcement lives in the application layer).
        """
        self._ensure_active()

        if self._is_trusted:
            raise DeviceAlreadyTrustedError()

        self._is_trusted = True

        self._record_event(
            DeviceTrusted(
                device_id=self._id.value,
                user_id=self._user_id.value,
            )
        )

    def untrust(self) -> None:
        """Downgrade a previously trusted device back to untrusted."""
        self._ensure_active()

        if not self._is_trusted:
            raise DeviceAlreadyUntrustedError()

        self._is_trusted = False

        self._record_event(
            DeviceUntrusted(
                device_id=self._id.value,
                user_id=self._user_id.value,
            )
        )

    def revoke(self) -> None:
        """
        Permanently revoke this device.
        The application layer is responsible for also revoking all
        Sessions that carry this device_id.
        """
        if self._status == DeviceStatus.REVOKED:
            raise DeviceAlreadyRevokedError()

        self._status = DeviceStatus.REVOKED
        self._is_trusted = False

        self._record_event(
            DeviceRevoked(
                device_id=self._id.value,
                user_id=self._user_id.value,
            )
        )

    def ensure_accessible_by(self, user_id: UserId) -> None:
        if self._user_id != user_id:
            raise DeviceOwnershipError()
        if not self.is_active:
            raise DeviceRevokedError()

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.event_handlers.base import EventHandler

if TYPE_CHECKING:
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.device_events import DeviceRegistered
    from pydentity.domain.events.session_events import RefreshTokenReused
    from pydentity.domain.events.user_events import (
        AccountLocked,
        PasswordChanged,
        PasswordResetRequested,
        UserDeactivated,
        UserRegistered,
        UserSuspended,
        VerificationTokenIssued,
    )


# ---------------------------------------------------------------------------
# UserRegistered
# ---------------------------------------------------------------------------


class OnUserRegistered(EventHandler["UserRegistered"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: UserRegistered) -> None:
        await self._notification.send_welcome_email(email=event.email)


# ---------------------------------------------------------------------------
# AccountLocked
# ---------------------------------------------------------------------------


class OnAccountLocked(EventHandler["AccountLocked"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: AccountLocked) -> None:
        await self._notification.send_account_locked_email(
            email=event.email,
            locked_until=str(event.locked_until),
        )


class OnPasswordChanged(EventHandler["PasswordChanged"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: PasswordChanged) -> None:
        await self._notification.send_password_changed_email(email=event.email)


class OnVerificationTokenIssued(EventHandler["VerificationTokenIssued"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: VerificationTokenIssued) -> None:
        await self._notification.send_verification_email(
            email=event.email,
            raw_token=event.raw_token,
        )


class OnPasswordResetRequested(EventHandler["PasswordResetRequested"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: PasswordResetRequested) -> None:
        await self._notification.send_password_reset_email(
            email=event.email,
            raw_token=event.raw_token,
        )


# ---------------------------------------------------------------------------
# UserSuspended
# ---------------------------------------------------------------------------


class OnUserSuspended(EventHandler["UserSuspended"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: UserSuspended) -> None:
        await self._notification.send_account_suspended_email(
            email=event.email,
            reason=event.reason,
        )


# ---------------------------------------------------------------------------
# UserDeactivated
# ---------------------------------------------------------------------------


class OnUserDeactivated(EventHandler["UserDeactivated"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: UserDeactivated) -> None:
        await self._notification.send_account_deactivated_email(
            email=event.email,
        )


# ---------------------------------------------------------------------------
# RefreshTokenReused
# ---------------------------------------------------------------------------


class OnRefreshTokenReused(EventHandler["RefreshTokenReused"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: RefreshTokenReused) -> None:
        if event.email is None:
            return
        await self._notification.send_refresh_token_reuse_alert(email=event.email)


# ---------------------------------------------------------------------------
# DeviceRegistered
# ---------------------------------------------------------------------------


class OnDeviceRegistered(EventHandler["DeviceRegistered"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: DeviceRegistered) -> None:
        if event.email is None:
            return
        await self._notification.send_new_device_email(
            email=event.email, device_name=event.device_name
        )

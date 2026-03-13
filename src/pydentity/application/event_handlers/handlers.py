from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.event_handlers.base import EventHandler

if TYPE_CHECKING:
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.user_events import (
        AccountLocked,
        PasswordChanged,
        UserDeactivated,
        UserRegistered,
        UserSuspended,
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

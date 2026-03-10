from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.event_handlers.base import EventHandler

if TYPE_CHECKING:
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.user_events import (
        AccountLocked,
        EmailVerified,
        LoginFailed,
        PasswordChanged,
        PasswordReset,
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


# ---------------------------------------------------------------------------
# LoginFailed
# ---------------------------------------------------------------------------


class OnLoginFailed(EventHandler["LoginFailed"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: LoginFailed) -> None:
        await self._notification.send_login_failed_alert(
            email=event.email,
            failed_attempts=event.failed_attempts,
        )


# ---------------------------------------------------------------------------
# PasswordReset
# ---------------------------------------------------------------------------


class OnPasswordReset(EventHandler["PasswordReset"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: PasswordReset) -> None:
        await self._notification.send_password_reset_confirmation(email=event.email)


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
# EmailVerified
# ---------------------------------------------------------------------------


class OnEmailVerified(EventHandler["EmailVerified"]):
    def __init__(self, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: EmailVerified) -> None:
        await self._notification.send_email_verified_email(email=event.email)

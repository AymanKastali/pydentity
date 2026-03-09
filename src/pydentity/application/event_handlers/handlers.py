from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.event_handlers.base import EventHandler

if TYPE_CHECKING:
    from pydentity.application.ports.audit_log import AuditLogPort
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.device_events import DeviceRegistered, DeviceRevoked
    from pydentity.domain.events.session_events import (
        RefreshTokenReused,
        SessionTerminated,
    )
    from pydentity.domain.events.user_events import (
        AccountLocked,
        EmailVerified,
        LoginFailed,
        LoginSucceeded,
        PasswordChanged,
        PasswordReset,
        PasswordResetRequested,
        RoleAssignedToUser,
        RoleRevokedFromUser,
        UserActivated,
        UserDeactivated,
        UserRegistered,
        UserSuspended,
        VerificationTokenIssued,
    )


# ---------------------------------------------------------------------------
# UserRegistered
# ---------------------------------------------------------------------------


class OnUserRegistered(EventHandler["UserRegistered"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: UserRegistered) -> None:
        await self._notification.send_welcome_email(email=event.email)
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
        )


# ---------------------------------------------------------------------------
# AccountLocked
# ---------------------------------------------------------------------------


class OnAccountLocked(EventHandler["AccountLocked"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: AccountLocked) -> None:
        await self._notification.send_account_locked_email(
            email=event.email,
            locked_until=str(event.locked_until),
        )
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            metadata={"locked_until": str(event.locked_until)},
        )


# ---------------------------------------------------------------------------
# LoginFailed
# ---------------------------------------------------------------------------


class OnLoginFailed(EventHandler["LoginFailed"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: LoginFailed) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            metadata={"failed_attempts": str(event.failed_attempts)},
        )
        await self._notification.send_login_failed_alert(
            email=event.email,
            failed_attempts=event.failed_attempts,
        )


# ---------------------------------------------------------------------------
# PasswordReset
# ---------------------------------------------------------------------------


class OnPasswordReset(EventHandler["PasswordReset"]):
    def __init__(self, notification: NotificationPort, audit_log: AuditLogPort) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: PasswordReset) -> None:
        await self._notification.send_password_reset_confirmation(email=event.email)
        await self._audit_log.record(action=event.name, user_id=event.user_id)


class OnPasswordChanged(EventHandler["PasswordChanged"]):
    def __init__(self, notification: NotificationPort, audit_log: AuditLogPort) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: PasswordChanged) -> None:
        await self._notification.send_password_changed_email(email=event.email)
        await self._audit_log.record(action=event.name, user_id=event.user_id)


# ---------------------------------------------------------------------------
# DeviceRegistered
# ---------------------------------------------------------------------------


class OnDeviceRegistered(EventHandler["DeviceRegistered"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: DeviceRegistered) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            device_id=event.device_id,
            metadata={"device_name": event.device_name},
        )


# ---------------------------------------------------------------------------
# DeviceRevoked
# ---------------------------------------------------------------------------


class OnDeviceRevoked(EventHandler["DeviceRevoked"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: DeviceRevoked) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            device_id=event.device_id,
            metadata={"device_name": event.device_name},
        )


# ---------------------------------------------------------------------------
# SessionTerminated
# ---------------------------------------------------------------------------


class OnSessionTerminated(EventHandler["SessionTerminated"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: SessionTerminated) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            session_id=event.session_id,
        )


# ---------------------------------------------------------------------------
# RefreshTokenReused
# ---------------------------------------------------------------------------


class OnRefreshTokenReused(EventHandler["RefreshTokenReused"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: RefreshTokenReused) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            session_id=event.session_id,
        )


class OnVerificationTokenIssued(EventHandler["VerificationTokenIssued"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: VerificationTokenIssued) -> None:
        await self._notification.send_verification_email(
            email=event.email,
            raw_token=event.raw_token,
        )
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
        )


class OnPasswordResetRequested(EventHandler["PasswordResetRequested"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: PasswordResetRequested) -> None:
        await self._notification.send_password_reset_email(
            email=event.email,
            raw_token=event.raw_token,
        )
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
        )


# ---------------------------------------------------------------------------
# UserSuspended
# ---------------------------------------------------------------------------


class OnUserSuspended(EventHandler["UserSuspended"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: UserSuspended) -> None:
        await self._notification.send_account_suspended_email(
            email=event.email,
            reason=event.reason,
        )
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            metadata={"reason": event.reason},
        )


# ---------------------------------------------------------------------------
# UserDeactivated
# ---------------------------------------------------------------------------


class OnUserDeactivated(EventHandler["UserDeactivated"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: UserDeactivated) -> None:
        await self._notification.send_account_deactivated_email(
            email=event.email,
        )
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
        )


# ---------------------------------------------------------------------------
# LoginSucceeded
# ---------------------------------------------------------------------------


class OnLoginSucceeded(EventHandler["LoginSucceeded"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: LoginSucceeded) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
        )


# ---------------------------------------------------------------------------
# RoleAssignedToUser
# ---------------------------------------------------------------------------


class OnRoleAssignedToUser(EventHandler["RoleAssignedToUser"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: RoleAssignedToUser) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            metadata={"role_id": event.role_id},
        )


# ---------------------------------------------------------------------------
# RoleRevokedFromUser
# ---------------------------------------------------------------------------


class OnRoleRevokedFromUser(EventHandler["RoleRevokedFromUser"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: RoleRevokedFromUser) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
            metadata={"role_id": event.role_id},
        )


# ---------------------------------------------------------------------------
# EmailVerified
# ---------------------------------------------------------------------------


class OnEmailVerified(EventHandler["EmailVerified"]):
    def __init__(
        self,
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._notification = notification
        self._audit_log = audit_log

    async def handle(self, event: EmailVerified) -> None:
        await self._notification.send_email_verified_email(email=event.email)
        await self._audit_log.record(action=event.name, user_id=event.user_id)


# ---------------------------------------------------------------------------
# UserActivated
# ---------------------------------------------------------------------------


class OnUserActivated(EventHandler["UserActivated"]):
    def __init__(self, audit_log: AuditLogPort) -> None:
        self._audit_log = audit_log

    async def handle(self, event: UserActivated) -> None:
        await self._audit_log.record(
            action=event.name,
            user_id=event.user_id,
        )

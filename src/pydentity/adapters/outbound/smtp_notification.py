from __future__ import annotations

import logging
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

import aiosmtplib

from pydentity.application.ports.notification import NotificationPort

if TYPE_CHECKING:
    from pydentity.adapters.config.smtp import SmtpSettings

_log = logging.getLogger("pydentity.notification")


class SmtpNotification(NotificationPort):
    def __init__(self, settings: SmtpSettings) -> None:
        self._settings = settings

    async def _send(self, *, to: str, subject: str, body: str) -> None:
        s = self._settings
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = f"{s.sender_name} <{s.sender}>"
        msg["To"] = to

        await aiosmtplib.send(
            msg,
            hostname=s.host,
            port=s.port,
            username=s.username or None,
            password=s.password.get_secret_value() if s.password else None,
            use_tls=s.use_tls,
            start_tls=s.use_starttls,
        )
        _log.debug("smtp sent subject=%r to=%s", subject, to)

    async def send_welcome_email(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Welcome to Pydentity",
            body="Your account has been created. Welcome!",
        )

    async def send_verification_email(self, *, email: str, raw_token: str) -> None:
        await self._send(
            to=email,
            subject="Verify your email address",
            body=f"Your verification token: {raw_token}",
        )

    async def send_account_exists_email(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Sign-in attempt",
            body=(
                "Someone tried to register with your email address. "
                "If this was you, please log in instead."
            ),
        )

    async def send_account_locked_email(self, *, email: str, locked_until: str) -> None:
        await self._send(
            to=email,
            subject="Account locked",
            body=(
                f"Your account has been locked until {locked_until} "
                "due to too many failed login attempts."
            ),
        )

    async def send_login_failed_alert(
        self, *, email: str, failed_attempts: int
    ) -> None:
        await self._send(
            to=email,
            subject="Failed login attempt",
            body=(
                f"There have been {failed_attempts} failed login attempt(s) "
                "on your account."
            ),
        )

    async def send_password_reset_confirmation(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Password reset successful",
            body="Your password has been reset successfully.",
        )

    async def send_password_changed_email(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Password changed",
            body=(
                "Your password has been changed. "
                "If you did not do this, contact support immediately."
            ),
        )

    async def send_new_device_email(self, *, email: str, device_name: str) -> None:
        await self._send(
            to=email,
            subject="New device logged in",
            body=(
                f"A new device ({device_name}) has been used to log in to your account."
            ),
        )

    async def send_device_revoked_email(self, *, email: str, device_name: str) -> None:
        await self._send(
            to=email,
            subject="Device revoked",
            body=f"The device ({device_name}) has been revoked from your account.",
        )

    async def send_session_terminated_email(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Session terminated",
            body="One of your active sessions has been terminated.",
        )

    async def send_refresh_token_reuse_alert(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Security alert: token reuse detected",
            body=(
                "A refresh token reuse was detected on your account. "
                "All sessions have been revoked. Please log in again."
            ),
        )

    async def send_password_reset_email(self, *, email: str, raw_token: str) -> None:
        await self._send(
            to=email,
            subject="Password reset request",
            body=f"Your password reset token: {raw_token}",
        )

    async def send_account_suspended_email(self, *, email: str, reason: str) -> None:
        await self._send(
            to=email,
            subject="Account suspended",
            body=f"Your account has been suspended. Reason: {reason}",
        )

    async def send_account_deactivated_email(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Account deactivated",
            body="Your account has been deactivated.",
        )

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

    async def send_password_changed_email(self, *, email: str) -> None:
        await self._send(
            to=email,
            subject="Password changed",
            body=(
                "Your password has been changed. "
                "If you did not do this, contact support immediately."
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

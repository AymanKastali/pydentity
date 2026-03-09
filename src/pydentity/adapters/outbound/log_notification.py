from __future__ import annotations

import logging

from pydentity.application.ports.notification import NotificationPort

_log = logging.getLogger("pydentity.notification")


def _redact(token: str) -> str:
    """Show only the last 4 characters of a token."""
    return f"***{token[-4:]}" if len(token) > 4 else "***"


class LogNotification(NotificationPort):
    async def send_welcome_email(self, *, email: str) -> None:
        _log.info("send_welcome_email to=%s", email)

    async def send_verification_email(self, *, email: str, raw_token: str) -> None:
        _log.info("send_verification_email to=%s token=%s", email, _redact(raw_token))

    async def send_account_exists_email(self, *, email: str) -> None:
        _log.info("send_account_exists_email to=%s", email)

    async def send_account_locked_email(self, *, email: str, locked_until: str) -> None:
        _log.info(
            "send_account_locked_email to=%s locked_until=%s", email, locked_until
        )

    async def send_login_failed_alert(
        self, *, email: str, failed_attempts: int
    ) -> None:
        _log.info("send_login_failed_alert to=%s attempts=%d", email, failed_attempts)

    async def send_password_reset_confirmation(self, *, email: str) -> None:
        _log.info("send_password_reset_confirmation to=%s", email)

    async def send_password_changed_email(self, *, email: str) -> None:
        _log.info("send_password_changed_email to=%s", email)

    async def send_new_device_email(self, *, email: str, device_name: str) -> None:
        _log.info("send_new_device_email to=%s device=%s", email, device_name)

    async def send_device_revoked_email(self, *, email: str, device_name: str) -> None:
        _log.info("send_device_revoked_email to=%s device=%s", email, device_name)

    async def send_session_terminated_email(self, *, email: str) -> None:
        _log.info("send_session_terminated_email to=%s", email)

    async def send_refresh_token_reuse_alert(self, *, email: str) -> None:
        _log.info("send_refresh_token_reuse_alert to=%s", email)

    async def send_password_reset_email(self, *, email: str, raw_token: str) -> None:
        _log.info("send_password_reset_email to=%s token=%s", email, _redact(raw_token))

    async def send_account_suspended_email(self, *, email: str, reason: str) -> None:
        _log.info("send_account_suspended_email to=%s reason=%s", email, reason)

    async def send_account_deactivated_email(self, *, email: str) -> None:
        _log.info("send_account_deactivated_email to=%s", email)

    async def send_email_verified_email(self, *, email: str) -> None:
        _log.info("send_email_verified_email to=%s", email)

from __future__ import annotations

from abc import ABC, abstractmethod


class NotificationPort(ABC):
    @abstractmethod
    async def send_welcome_email(self, *, email: str) -> None: ...

    @abstractmethod
    async def send_verification_email(self, *, email: str, raw_token: str) -> None: ...

    @abstractmethod
    async def send_account_exists_email(self, *, email: str) -> None: ...

    @abstractmethod
    async def send_account_locked_email(
        self, *, email: str, locked_until: str
    ) -> None: ...

    @abstractmethod
    async def send_login_failed_alert(
        self, *, email: str, failed_attempts: int
    ) -> None: ...

    @abstractmethod
    async def send_password_reset_confirmation(self, *, email: str) -> None: ...

    @abstractmethod
    async def send_password_changed_email(self, *, email: str) -> None: ...

    @abstractmethod
    async def send_new_device_email(self, *, email: str, device_name: str) -> None: ...

    @abstractmethod
    async def send_device_revoked_email(
        self, *, email: str, device_name: str
    ) -> None: ...

    @abstractmethod
    async def send_session_terminated_email(self, *, email: str) -> None: ...

    @abstractmethod
    async def send_refresh_token_reuse_alert(self, *, email: str) -> None: ...

    @abstractmethod
    async def send_password_reset_email(
        self, *, email: str, raw_token: str
    ) -> None: ...

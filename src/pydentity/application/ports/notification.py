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
    async def send_password_changed_email(self, *, email: str) -> None: ...

    @abstractmethod
    async def send_password_reset_email(
        self, *, email: str, raw_token: str
    ) -> None: ...

    @abstractmethod
    async def send_account_suspended_email(
        self, *, email: str, reason: str
    ) -> None: ...

    @abstractmethod
    async def send_account_deactivated_email(self, *, email: str) -> None: ...

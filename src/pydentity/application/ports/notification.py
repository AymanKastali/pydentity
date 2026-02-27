from __future__ import annotations

from abc import ABC, abstractmethod


class NotificationPort(ABC):
    @abstractmethod
    async def send_verification_email(self, *, email: str, raw_token: str) -> None: ...

    @abstractmethod
    async def send_password_reset_email(
        self, *, email: str, raw_token: str
    ) -> None: ...

    @abstractmethod
    async def send_welcome_email(self, *, email: str) -> None: ...

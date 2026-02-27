from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.user_events import UserRegistered


class SendWelcomeEmailOnRegistration:
    def __init__(self, *, notification: NotificationPort) -> None:
        self._notification = notification

    async def handle(self, event: UserRegistered) -> None:
        await self._notification.send_welcome_email(email=event.email)

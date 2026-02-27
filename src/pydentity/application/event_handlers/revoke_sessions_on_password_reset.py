from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.event_handlers._revoke_sessions import (
    _RevokeSessionsHandler,
)

if TYPE_CHECKING:
    from pydentity.domain.events.user_events import PasswordReset


class RevokeSessionsOnPasswordReset(_RevokeSessionsHandler):
    async def handle(self, event: PasswordReset) -> None:
        await self._revoke_all(event.user_id)

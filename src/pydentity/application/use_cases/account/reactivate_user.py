from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.use_cases.account._base import SingleUserCommand

if TYPE_CHECKING:
    from pydentity.application.dtos.account import ReactivateUserInput


class ReactivateUser(SingleUserCommand):
    async def execute(self, command: ReactivateUserInput) -> None:
        await self._execute_on_user(
            user_id=command.user_id,
            action=lambda user: user.reactivate(),
            log_message="user reactivated",
        )

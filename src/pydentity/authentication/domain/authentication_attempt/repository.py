from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.authentication.domain.authentication_attempt.aggregate import (
        AuthenticationAttempt,
    )
    from pydentity.authentication.domain.authentication_attempt.aggregate_id import (
        AuthAttemptId,
    )


class AuthenticationAttemptRepository(ABC):
    @abstractmethod
    async def save(self, attempt: AuthenticationAttempt) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, attempt_id: AuthAttemptId
    ) -> AuthenticationAttempt | None: ...

    @abstractmethod
    async def delete_expired(self, now: datetime) -> None: ...

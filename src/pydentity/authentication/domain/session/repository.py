from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.authentication.domain.session.aggregate import Session
    from pydentity.authentication.domain.session.aggregate_id import SessionId
    from pydentity.shared_kernel import AccountId


class SessionRepository(ABC):
    @abstractmethod
    async def save(self, session: Session) -> None: ...

    @abstractmethod
    async def find_by_id(self, session_id: SessionId) -> Session | None: ...

    @abstractmethod
    async def find_active_by_account_id(
        self, account_id: AccountId
    ) -> list[Session]: ...

    @abstractmethod
    async def find_by_refresh_token_hash(self, token_hash: str) -> Session | None: ...

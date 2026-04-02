from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.authentication.domain.identity.aggregate import Identity
    from pydentity.shared_kernel import IdentityId


class IdentityRepository(ABC):
    @abstractmethod
    async def save(self, identity: Identity) -> None: ...

    @abstractmethod
    async def find_by_id(self, identity_id: IdentityId) -> Identity | None: ...

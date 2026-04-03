from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.audit.domain.audit_entry.aggregate import AuditEntry
    from pydentity.audit.domain.audit_entry.aggregate_id import AuditEntryId
    from pydentity.shared_kernel import AccountId


class AuditEntryRepository(ABC):
    @abstractmethod
    async def save(self, entry: AuditEntry) -> None: ...

    @abstractmethod
    async def find_by_id(self, entry_id: AuditEntryId) -> AuditEntry | None: ...

    @abstractmethod
    async def find_by_account_id(self, account_id: AccountId) -> list[AuditEntry]: ...

    @abstractmethod
    async def find_by_event_name(self, event_name: str) -> list[AuditEntry]: ...

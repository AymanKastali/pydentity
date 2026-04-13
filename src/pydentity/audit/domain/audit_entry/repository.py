from abc import ABC, abstractmethod

from pydentity.audit.domain.audit_entry.aggregate import AuditEntry
from pydentity.audit.domain.audit_entry.value_objects import AuditEntryId
from pydentity.shared_kernel.building_blocks import EventName
from pydentity.shared_kernel.value_objects import AccountId


class AuditEntryRepository(ABC):
    @abstractmethod
    async def save(self, entry: AuditEntry) -> None: ...

    @abstractmethod
    async def find_by_id(self, entry_id: AuditEntryId) -> AuditEntry | None: ...

    @abstractmethod
    async def find_by_account_id(self, account_id: AccountId) -> list[AuditEntry]: ...

    @abstractmethod
    async def find_by_event_name(self, event_name: EventName) -> list[AuditEntry]: ...

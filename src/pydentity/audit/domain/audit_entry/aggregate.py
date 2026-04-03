from typing import TYPE_CHECKING

from pydentity.audit.domain.audit_entry.aggregate_id import AuditEntryId
from pydentity.shared_kernel import AggregateRoot

if TYPE_CHECKING:
    from pydentity.audit.domain.audit_entry.value_objects import EventPayload
    from pydentity.shared_kernel import AccountId


class AuditEntry(AggregateRoot[AuditEntryId]):
    def __init__(
        self,
        entry_id: AuditEntryId,
        event_name: str,
        account_id: AccountId,
        payload: EventPayload,
    ) -> None:
        super().__init__(entry_id)
        self._event_name: str = event_name
        self._account_id: AccountId = account_id
        self._payload: EventPayload = payload

    # --- Creation ---

    @classmethod
    def record(
        cls,
        entry_id: AuditEntryId,
        event_name: str,
        account_id: AccountId,
        payload: EventPayload,
    ) -> AuditEntry:
        return cls(
            entry_id=entry_id,
            event_name=event_name,
            account_id=account_id,
            payload=payload,
        )

    # --- Queries ---

    @property
    def event_name(self) -> str:
        return self._event_name

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def payload(self) -> EventPayload:
        return self._payload

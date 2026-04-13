from typing import Self

from pydentity.audit.domain.audit_entry.value_objects import AuditEntryId, EventPayload
from pydentity.shared_kernel.building_blocks import AggregateRoot, EventName
from pydentity.shared_kernel.value_objects import AccountId


class AuditEntry(AggregateRoot[AuditEntryId]):
    def __init__(
        self,
        entry_id: AuditEntryId,
        event_name: EventName,
        account_id: AccountId,
        payload: EventPayload,
    ) -> None:
        super().__init__(entry_id)
        self._event_name: EventName = event_name
        self._account_id: AccountId = account_id
        self._payload: EventPayload = payload

    @classmethod
    def record(
        cls,
        entry_id: AuditEntryId,
        event_name: EventName,
        account_id: AccountId,
        payload: EventPayload,
    ) -> Self:
        return cls(
            entry_id=entry_id,
            event_name=event_name,
            account_id=account_id,
            payload=payload,
        )

    @property
    def event_name(self) -> EventName:
        return self._event_name

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def payload(self) -> EventPayload:
        return self._payload

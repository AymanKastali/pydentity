from uuid import uuid4

from pydentity.audit.domain.audit_entry.aggregate import AuditEntry
from pydentity.audit.domain.audit_entry.aggregate_id import AuditEntryId
from pydentity.audit.domain.audit_entry.value_objects import EventPayload
from pydentity.shared_kernel import AccountId


class TestAuditEntryRecord:
    def test_creates_audit_entry(self, account_id: AccountId):
        entry_id = AuditEntryId(value=uuid4())
        payload = EventPayload(entries=(("key", "value"),))
        entry = AuditEntry.record(entry_id, "account_registered", account_id, payload)
        assert entry.id == entry_id

    def test_stores_event_name(self, account_id: AccountId):
        entry_id = AuditEntryId(value=uuid4())
        payload = EventPayload(entries=())
        entry = AuditEntry.record(entry_id, "account_registered", account_id, payload)
        assert entry.event_name == "account_registered"

    def test_stores_account_id(self, account_id: AccountId):
        entry_id = AuditEntryId(value=uuid4())
        payload = EventPayload(entries=())
        entry = AuditEntry.record(entry_id, "account_registered", account_id, payload)
        assert entry.account_id == account_id

    def test_stores_payload(self, account_id: AccountId):
        entry_id = AuditEntryId(value=uuid4())
        payload = EventPayload(entries=(("key", "value"),))
        entry = AuditEntry.record(entry_id, "account_registered", account_id, payload)
        assert entry.payload == payload

    def test_records_no_domain_events(self, account_id: AccountId):
        entry_id = AuditEntryId(value=uuid4())
        payload = EventPayload(entries=())
        entry = AuditEntry.record(entry_id, "account_registered", account_id, payload)
        assert entry.events == []

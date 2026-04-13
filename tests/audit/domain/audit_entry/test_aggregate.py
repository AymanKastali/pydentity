from uuid import uuid4

from pydentity.audit.domain.audit_entry.aggregate import AuditEntry
from pydentity.audit.domain.audit_entry.value_objects import AuditEntryId, EventPayload
from pydentity.shared_kernel.building_blocks import AggregateRoot, EventName
from pydentity.shared_kernel.value_objects import AccountId


def _make_entry() -> AuditEntry:
    return AuditEntry.record(
        entry_id=AuditEntryId(value=uuid4()),
        event_name=EventName(value="AccountRegistered"),
        account_id=AccountId(value=uuid4()),
        payload=EventPayload(entries=(("reason", "signup"),)),
    )


class TestAuditEntry:
    def test_record_factory_creates_entry(self):
        entry_id = AuditEntryId(value=uuid4())
        event_name = EventName(value="AccountRegistered")
        account_id = AccountId(value=uuid4())
        payload = EventPayload(entries=(("reason", "signup"),))

        entry = AuditEntry.record(
            entry_id=entry_id,
            event_name=event_name,
            account_id=account_id,
            payload=payload,
        )

        assert entry.id == entry_id
        assert entry.event_name == event_name
        assert entry.account_id == account_id
        assert entry.payload == payload

    def test_is_aggregate_root(self):
        entry = _make_entry()
        assert isinstance(entry, AggregateRoot)

    def test_identity_equality(self):
        uid = uuid4()
        entry_id = AuditEntryId(value=uid)
        a = AuditEntry.record(
            entry_id=entry_id,
            event_name=EventName(value="X"),
            account_id=AccountId(value=uuid4()),
            payload=EventPayload(entries=()),
        )
        b = AuditEntry.record(
            entry_id=entry_id,
            event_name=EventName(value="Y"),
            account_id=AccountId(value=uuid4()),
            payload=EventPayload(entries=()),
        )
        assert a == b

    def test_not_equal_different_ids(self):
        a = _make_entry()
        b = _make_entry()
        assert a != b

    def test_no_domain_events_after_creation(self):
        entry = _make_entry()
        assert entry.events == []

    def test_hash_by_identity(self):
        uid = uuid4()
        entry_id = AuditEntryId(value=uid)
        a = AuditEntry.record(
            entry_id=entry_id,
            event_name=EventName(value="X"),
            account_id=AccountId(value=uuid4()),
            payload=EventPayload(entries=()),
        )
        b = AuditEntry.record(
            entry_id=entry_id,
            event_name=EventName(value="Y"),
            account_id=AccountId(value=uuid4()),
            payload=EventPayload(entries=()),
        )
        assert hash(a) == hash(b)

from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from pydentity.audit.domain.audit_entry.value_objects import AuditEntryId
from pydentity.shared_kernel.building_blocks import ValueObject


class TestAuditEntryId:
    def test_stores_uuid(self):
        uid = uuid4()
        entry_id = AuditEntryId(value=uid)
        assert entry_id.value == uid

    def test_frozen(self):
        entry_id = AuditEntryId(value=uuid4())
        with pytest.raises(FrozenInstanceError):
            entry_id.value = uuid4()  # type: ignore[misc]

    def test_equal_by_value(self):
        uid = uuid4()
        assert AuditEntryId(value=uid) == AuditEntryId(value=uid)

    def test_not_equal_when_values_differ(self):
        assert AuditEntryId(value=uuid4()) != AuditEntryId(value=uuid4())

    def test_hashable(self):
        uid = uuid4()
        a = AuditEntryId(value=uid)
        b = AuditEntryId(value=uid)
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_is_value_object(self):
        entry_id = AuditEntryId(value=uuid4())
        assert isinstance(entry_id, ValueObject)

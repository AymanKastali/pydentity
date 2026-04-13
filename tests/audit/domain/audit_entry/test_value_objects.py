from dataclasses import FrozenInstanceError

import pytest

from pydentity.audit.domain.audit_entry.value_objects import EventPayload
from pydentity.shared_kernel.building_blocks import ValueObject


class TestEventPayload:
    def test_valid_creation(self):
        entries = (("account_id", "abc-123"), ("reason", "threshold"))
        payload = EventPayload(entries=entries)
        assert payload.entries == entries

    def test_empty_entries(self):
        payload = EventPayload(entries=())
        assert payload.entries == ()

    def test_frozen(self):
        payload = EventPayload(entries=(("k", "v"),))
        with pytest.raises(FrozenInstanceError):
            payload.entries = ()  # type: ignore[misc]

    def test_equal_by_value(self):
        entries = (("k", "v"),)
        assert EventPayload(entries=entries) == EventPayload(entries=entries)

    def test_hashable(self):
        entries = (("k", "v"),)
        a = EventPayload(entries=entries)
        b = EventPayload(entries=entries)
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_exceeding_max_entries_raises(self):
        entries = tuple(("k", "v") for _ in range(51))
        with pytest.raises(ValueError):
            EventPayload(entries=entries)

    def test_at_max_entries_is_valid(self):
        entries = tuple(("k", "v") for _ in range(50))
        payload = EventPayload(entries=entries)
        assert len(payload.entries) == 50

    def test_key_exceeding_max_length_raises(self):
        entries = (("k" * 101, "v"),)
        with pytest.raises(ValueError):
            EventPayload(entries=entries)

    def test_value_exceeding_max_length_raises(self):
        entries = (("k", "v" * 501),)
        with pytest.raises(ValueError):
            EventPayload(entries=entries)

    def test_is_value_object(self):
        payload = EventPayload(entries=())
        assert isinstance(payload, ValueObject)

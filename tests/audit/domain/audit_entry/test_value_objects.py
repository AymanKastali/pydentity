import pytest

from pydentity.audit.domain.audit_entry.value_objects import EventPayload


class TestEventPayload:
    def test_valid_creation(self):
        payload = EventPayload(entries=(("key", "value"),))
        assert payload.entries == (("key", "value"),)

    def test_allows_empty_entries(self):
        payload = EventPayload(entries=())
        assert payload.entries == ()

    def test_rejects_exceeding_max_entries(self):
        entries = tuple((f"key{i}", f"val{i}") for i in range(51))
        with pytest.raises(ValueError):
            EventPayload(entries=entries)

    def test_rejects_key_exceeding_max_length(self):
        with pytest.raises(ValueError):
            EventPayload(entries=(("k" * 101, "value"),))

    def test_rejects_value_exceeding_max_length(self):
        with pytest.raises(ValueError):
            EventPayload(entries=(("key", "v" * 501),))

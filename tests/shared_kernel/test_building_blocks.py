from dataclasses import FrozenInstanceError, dataclass
from uuid import UUID, uuid4

import pytest

from pydentity.shared_kernel.building_blocks import (
    AggregateRoot,
    DomainError,
    DomainEvent,
    Entity,
    EventName,
    ValueObject,
)


# ── Concrete test doubles ──


@dataclass(frozen=True, slots=True)
class _Price(ValueObject):
    amount: int
    currency: str


@dataclass(frozen=True, slots=True)
class _FakeEvent(DomainEvent):
    detail: str


class _FakeEntity(Entity[UUID]):
    pass


class _FakeAggregate(AggregateRoot[UUID]):
    pass


class _OtherEntity(Entity[UUID]):
    pass


# ── ValueObject ──


class TestValueObject:
    def test_equal_by_value(self):
        assert _Price(amount=10, currency="USD") == _Price(amount=10, currency="USD")

    def test_not_equal_when_values_differ(self):
        assert _Price(amount=10, currency="USD") != _Price(amount=20, currency="USD")

    def test_frozen(self):
        price = _Price(amount=10, currency="USD")
        with pytest.raises(FrozenInstanceError):
            price.amount = 99  # type: ignore[misc]

    def test_hashable(self):
        a = _Price(amount=10, currency="USD")
        b = _Price(amount=10, currency="USD")
        assert hash(a) == hash(b)
        assert {a, b} == {a}


# ── DomainEvent ──


class TestDomainEvent:
    def test_carries_event_name(self):
        event = _FakeEvent(detail="item-1")
        assert event.name == EventName("_FakeEvent")
        assert event.detail == "item-1"

    def test_frozen(self):
        event = _FakeEvent(detail="item-1")
        with pytest.raises(FrozenInstanceError):
            event.detail = "changed"  # type: ignore[misc]

    def test_equal_by_value(self):
        a = _FakeEvent(detail="d")
        b = _FakeEvent(detail="d")
        assert a == b

    def test_is_value_object(self):
        event = _FakeEvent(detail="d")
        assert isinstance(event, ValueObject)


# ── DomainError ──


class TestDomainError:
    def test_message_property(self):
        error = DomainError("Something went wrong.")
        assert error.message == "Something went wrong."

    def test_is_exception(self):
        assert issubclass(DomainError, Exception)

    def test_raisable_and_catchable(self):
        with pytest.raises(DomainError, match="boom"):
            raise DomainError("boom")

    def test_str_representation(self):
        error = DomainError("test message")
        assert str(error) == "test message"


# ── Entity ──


class TestEntity:
    def test_identity_property(self):
        uid = uuid4()
        entity = _FakeEntity(uid)
        assert entity.id == uid

    def test_equal_by_identity(self):
        uid = uuid4()
        a = _FakeEntity(uid)
        b = _FakeEntity(uid)
        assert a == b

    def test_not_equal_different_id(self):
        a = _FakeEntity(uuid4())
        b = _FakeEntity(uuid4())
        assert a != b

    def test_not_equal_different_type(self):
        uid = uuid4()
        entity = _FakeEntity(uid)
        other = _OtherEntity(uid)
        assert entity != other

    def test_hash_by_identity(self):
        uid = uuid4()
        a = _FakeEntity(uid)
        b = _FakeEntity(uid)
        assert hash(a) == hash(b)

    def test_not_equal_to_non_entity(self):
        entity = _FakeEntity(uuid4())
        assert entity != "not an entity"


# ── AggregateRoot ──


class TestAggregateRoot:
    def test_starts_with_no_events(self):
        agg = _FakeAggregate(uuid4())
        assert agg.events == []

    def test_record_event(self):
        agg = _FakeAggregate(uuid4())
        event = _FakeEvent(detail="d")
        agg.record_event(event)
        assert agg.events == [event]

    def test_record_multiple_events(self):
        agg = _FakeAggregate(uuid4())
        e1 = _FakeEvent(detail="1")
        e2 = _FakeEvent(detail="2")
        agg.record_event(e1)
        agg.record_event(e2)
        assert agg.events == [e1, e2]

    def test_clear_events(self):
        agg = _FakeAggregate(uuid4())
        event = _FakeEvent(detail="d")
        agg.record_event(event)
        assert agg.events == [event]
        agg.clear_events()
        assert agg.events == []

    def test_events_returns_copy(self):
        agg = _FakeAggregate(uuid4())
        event = _FakeEvent(detail="d")
        agg.record_event(event)
        events = agg.events
        events.clear()
        assert agg.events == [event]

    def test_is_entity(self):
        agg = _FakeAggregate(uuid4())
        assert isinstance(agg, Entity)

    def test_identity_equality(self):
        uid = uuid4()
        a = _FakeAggregate(uid)
        b = _FakeAggregate(uid)
        assert a == b

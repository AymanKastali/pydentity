from dataclasses import FrozenInstanceError, dataclass
from datetime import UTC, datetime

import pytest

from pydentity.shared_kernel import (
    AggregateRoot,
    DomainError,
    DomainEvent,
    Entity,
    ValueObject,
)

# --- Concrete subclasses for testing ---


@dataclass(frozen=True, slots=True)
class Money(ValueObject):
    amount: int
    currency: str


@dataclass(frozen=True, slots=True)
class OrderPlaced(DomainEvent):
    order_id: str


class Order(AggregateRoot[str]):
    pass


class Product(Entity[int]):
    pass


# --- ValueObject ---


class TestValueObject:
    def test_equality_same_values(self):
        assert Money(amount=100, currency="USD") == Money(amount=100, currency="USD")

    def test_inequality_different_values(self):
        assert Money(amount=100, currency="USD") != Money(amount=200, currency="USD")

    def test_is_frozen(self):
        money = Money(amount=100, currency="USD")
        with pytest.raises(FrozenInstanceError):
            money.amount = 200  # type: ignore[misc]


# --- DomainEvent ---


class TestDomainEvent:
    def test_stores_occurred_at(self):
        occurred_at = datetime(2026, 1, 1, tzinfo=UTC)
        event = OrderPlaced(occurred_at=occurred_at, order_id="123")
        assert event.occurred_at == occurred_at

    def test_name_returns_class_name(self):
        occurred_at = datetime(2026, 1, 1, tzinfo=UTC)
        event = OrderPlaced(occurred_at=occurred_at, order_id="123")
        assert event.name == "OrderPlaced"

    def test_name_preserves_acronyms(self):
        @dataclass(frozen=True, slots=True)
        class MFAEnabled(DomainEvent):
            pass

        event = MFAEnabled(occurred_at=datetime(2026, 1, 1, tzinfo=UTC))
        assert event.name == "MFAEnabled"


# --- DomainError ---


class TestDomainError:
    def test_stores_message(self):
        error = DomainError("Something went wrong.")
        assert error.message == "Something went wrong."

    def test_is_exception(self):
        assert issubclass(DomainError, Exception)

    def test_str_representation(self):
        error = DomainError("broken")
        assert str(error) == "broken"


# --- Entity ---


class TestEntity:
    def test_stores_id(self):
        product = Product(entity_id=42)
        assert product.id == 42

    def test_equality_same_id(self):
        assert Product(entity_id=1) == Product(entity_id=1)

    def test_inequality_different_id(self):
        assert Product(entity_id=1) != Product(entity_id=2)

    def test_inequality_different_type(self):
        class Widget(Entity[int]):
            pass

        assert Product(entity_id=1) != Widget(entity_id=1)

    def test_inequality_with_non_entity(self):
        assert Product(entity_id=1) != "not an entity"

    def test_hash_matches_id_hash(self):
        product = Product(entity_id=42)
        assert hash(product) == hash(42)


# --- AggregateRoot ---


class TestAggregateRoot:
    def test_starts_with_no_events(self):
        order = Order(entity_id="order-1")
        assert order.events == []

    def test_record_event_adds_to_list(self):
        order = Order(entity_id="order-1")
        event = OrderPlaced(
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
            order_id="order-1",
        )
        order.record_event(event)
        assert len(order.events) == 1
        assert order.events[0] is event

    def test_events_returns_copy(self):
        order = Order(entity_id="order-1")
        events = order.events
        events.append(
            OrderPlaced(
                occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
                order_id="x",
            )
        )
        assert order.events == []

    def test_clear_events_empties_list(self):
        order = Order(entity_id="order-1")
        order.record_event(
            OrderPlaced(
                occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
                order_id="order-1",
            )
        )
        order.clear_events()
        assert order.events == []

    def test_multiple_events_preserves_order(self):
        order = Order(entity_id="order-1")
        event_1 = OrderPlaced(
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
            order_id="1",
        )
        event_2 = OrderPlaced(
            occurred_at=datetime(2026, 1, 2, tzinfo=UTC),
            order_id="2",
        )
        order.record_event(event_1)
        order.record_event(event_2)
        assert order.events == [event_1, event_2]

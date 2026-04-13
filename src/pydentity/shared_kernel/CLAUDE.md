# Shared Kernel

Cross-cutting DDD building blocks and shared value objects used by all bounded contexts.

**Impact:** Changes here affect every bounded context. Modify with care.

---

## Building Block Base Types

Defined in `building_blocks.py`:

| Base Type | Purpose |
|-----------|---------|
| `ValueObject` | Abstract base for all value objects. Frozen dataclass with slots. |
| `DomainEvent` | Abstract base for all domain events. Carries `name: EventName`. |
| `DomainError` | Abstract base for all domain errors. Carries `message: str`. |
| `Entity[TId]` | Generic entity base. Identity-based equality and hashing via `_id: TId`. |
| `AggregateRoot[TId]` | Extends `Entity[TId]`. Tracks domain events via `record_event()` / `clear_events()`. |

## Shared Value Objects

Defined in `value_objects.py`:

| Value Object | Fields | Used By |
|-------------|--------|---------|
| `AccountId` | `value: UUID` | Authentication, Audit, Notification |
| `DeviceId` | `value: UUID` | Authentication |

`EventName` (`value: str`) is defined in `building_blocks.py` alongside the base types. Used by Audit to classify audit entries.

## Guard Functions

Defined in `guards.py`. Used in value object `__post_init__` to enforce domain constraints. All raise `ValueError` on violation.

| Category | Guards |
|----------|--------|
| String | `guard_not_empty`, `guard_not_blank`, `guard_within_max_length` |
| Numeric | `guard_not_negative`, `guard_positive`, `guard_within_max`, `guard_within_min`, `guard_within_range` |
| Collection | `guard_not_empty_collection`, `guard_within_max_size`, `guard_no_duplicates`, `guard_all_positive`, `guard_all_within_max` |
| Temporal | `guard_before` |
| Comparison | `guard_min_not_greater_than_max` |

## Rules

- All value objects must be frozen dataclasses with slots inheriting from `ValueObject`
- All aggregates must inherit from `AggregateRoot[TId]` and record events via `record_event()`
- All domain errors must inherit from `DomainError`
- Entities use identity-based equality (`__eq__` and `__hash__` on `_id`) — never attribute-based
- Guard functions are the standard validation mechanism — do not use raw `assert` or inline validation

## References

- UML: `docs/diagrams/uml/shared_kernel/building_blocks.puml`, `docs/diagrams/uml/shared_kernel/shared_kernel.puml`
- Design: `docs/domain/tactical-design.md` (Shared Kernel section)

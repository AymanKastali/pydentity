# DDD Rules — Domain Model Purity & Tactical Patterns

## 1. Aggregate Purity

Aggregates are pure domain state machines. They must not depend on infrastructure or service interfaces.

- **Accept only value objects and `datetime`** — never primitives (`str`, `int`), never service interfaces (ABCs).
- **Properties return value objects** — never unwrap VOs to primitives.
- **No service injection** — aggregates are "newable types," not injectable services. They must never import or reference infrastructure ABCs.
- **Guards, state transitions, and event recording** remain inside the aggregate — these are pure domain logic.

## 2. Value Object Purity

Value objects are immutable, identity-less, and self-validating. They must not depend on service interfaces.

- **No interfaces accepted** — not in constructors, not in methods.
- **Pure behavior methods only** — methods that operate on the VO's own data and return new VO instances.
- **Absolute bounds are `ClassVar`** — domain invariants enforced internally, not configurable by callers.
- **Self-contained validation** — `__post_init__` guards ensure the VO is always valid.

## 3. Domain Services

Domain services contain domain logic that requires infrastructure interaction or spans multiple domain objects.

- **Verb-based names** per Evans — no `Service` suffix.
- **Stateless** — all methods are `@classmethod`.
- **Concrete classes** in the domain layer — they contain domain logic, not infrastructure logic.
- **Accept infrastructure ABCs as method parameters** — this is the designated place for service interface usage in the domain layer.
- **Read aggregate state via properties, return VOs or raise domain errors.**

## 4. Factory Pattern

Factories encapsulate aggregate creation and ensure aggregates are born in a valid state. In this project, factories are implemented as **classmethod factories on the aggregate itself** (e.g., `Account.register()`, `Session.start()`, `Identity.create()`), not as separate factory classes.

- **Classmethod on the aggregate** — the factory is a `@classmethod` that returns a new instance of the aggregate.
- **Accept per-request data as parameters** — the minimum input to produce a valid aggregate (value objects and `datetime` only).
- **Ensure aggregates are born valid** — all invariants satisfied from creation, initial events recorded.
- **Infrastructure-dependent creation logic** (hashing, ID generation) is handled by the application layer before calling the factory.

## 5. Application Services

Application services orchestrate use cases. They contain no domain logic.

- **Speak domain language** — pass value objects to domain methods, not primitives.
- **Orchestrate the flow**: read aggregate → call domain service → call aggregate command → save aggregate.
- **Hold infrastructure dependencies** via dependency injection.
- **No business rules** — all domain decisions live in aggregates or domain services.

## 6. The DDD Trilemma (Khorikov)

Three attributes of a domain model — you can only have two:

1. **Domain model completeness** — all domain logic in the domain layer.
2. **Domain model purity** — no infrastructure dependencies in domain classes.
3. **Performance** — no unnecessary calls to external systems.

**Choose purity + performance.** Accept split decision-making: infrastructure-dependent domain logic lives in domain services, pure domain logic lives in aggregates and value objects. This is the "push to the edges" approach.

## 7. Property Exposure

Aggregates expose read-only VO properties so that domain services and application services can read aggregate state without breaking encapsulation.

- Properties are **read-only** — no setters.
- Properties return **value objects** — the same VOs stored internally.
- Domain services use these properties to perform infrastructure-dependent checks.

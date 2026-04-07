# Shared Kernel

Minimal, stable foundation shared by all bounded contexts.

## Contents

Base classes (AggregateRoot, Entity, ValueObject, DomainEvent, DomainError), aggregate IDs (IdentityId, AccountId), and validation guards.

## Rules

- **Keep it minimal.** Only DDD tactical building blocks, cross-boundary identifiers, and reusable guards belong here. If something is context-specific, it belongs in that bounded context.
- **No context-specific concepts.** Passwords, TOTP secrets, sessions, audit entries, delivery requests — none of these belong here regardless of how many contexts reference them.
- **Aggregate IDs cross boundaries via events.** IdentityId and AccountId are here because they appear in domain events consumed by Audit and Notification. Other aggregate IDs (SessionId, AuthAttemptId, etc.) are also here for the same reason.
- **Guards raise ValueError.** Shared guards (guard_not_empty, guard_positive, guard_within_max_length, etc.) raise ValueError with descriptive messages. This is intentional for domain-layer input validation.
- **Stability is paramount.** Changes to shared kernel affect all bounded contexts. Treat modifications with extra caution.

# CLAUDE.md — pydentity

## Rules

All engineering standards live in `.claude/rules/` and are auto-loaded by Claude Code when relevant:

1. **[Clean Code](.claude/rules/clean_code.md)** — SOLID, DRY, CQS, naming, functions, OOP, readability, error handling, simplicity
2. **[Python Rules](.claude/rules/python_rules.md)** — Python-specific conventions: ABC vs Protocol, PEP 695 generics, enums, imports, dataclasses, naming, typing
3. **[DDD Deep Dive](.claude/rules/auth-ddd-deep-dive.md)** — strategic design, tactical patterns, aggregates, value objects, domain events, repositories, factories
4. **[Bounded Contexts](.claude/rules/auth-bounded-contexts.md)** — bounded context definitions and boundaries
5. **[Context Map](.claude/rules/auth-context-map.md)** — relationships between bounded contexts
6. **[Event Storming](.claude/rules/auth-event-storming.md)** — domain events, commands, aggregates discovered through event storming
7. **[Ubiquitous Language](.claude/rules/auth-ubiquitous-language.md)** — domain terminology and definitions
8. **[Tactical Design](.claude/rules/auth-tactical-design.md)** — aggregates, entities, behaviors, value objects, repositories, factories, domain services
9. **[Audit & Notification](.claude/rules/auth-tactical-audit-notification.md)** — audit logging and notification context tactical design
10. **[Refactoring](.claude/rules/refactoring.md)** — refactoring discipline, code smells, key techniques, and boundaries

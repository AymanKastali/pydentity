# CLAUDE.md — pydentity

## Rules

All engineering standards live in `.claude/rules/` and are auto-loaded by Claude Code when relevant:

1. **[Clean Code](.claude/rules/clean_code.md)** — SOLID, DRY, CQS, naming, functions, OOP, readability, error handling, simplicity
2. **[Python Rules](.claude/rules/python_rules.md)** — Python-specific conventions: ABC vs Protocol, PEP 695 generics, enums, imports, dataclasses, naming, typing
3. **[Strategic Design](.claude/rules/auth-strategic-design.md)** — bounded contexts, context map, subdomain boundaries, external contracts
4. **[Event Storming](.claude/rules/auth-event-storming.md)** — 23 scenario walkthroughs (command → aggregate → event flows)
5. **[Tactical Design](.claude/rules/auth-tactical-design.md)** — Authentication context: aggregates, value objects, behaviors, repositories, services, factories
6. **[Audit & Notification](.claude/rules/auth-tactical-audit-notification.md)** — Audit & Notification tactical design, canonical event contract lists
7. **[Refactoring](.claude/rules/refactoring.md)** — refactoring discipline, code smells, key techniques, and boundaries

Human-readable domain glossary: [docs/domain/ubiquitous-language.md](docs/domain/ubiquitous-language.md)

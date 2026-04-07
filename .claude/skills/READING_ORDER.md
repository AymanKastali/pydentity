# Skills — Recommended Reading Order

This reading order is designed for humans learning these skills from scratch. Each skill builds on concepts from the previous ones. AI agents can load any skill independently — the reading order is for human comprehension.

## The Path

| # | Skill | Focus | Prerequisites | What You'll Learn |
| --- | --- | --- | --- | --- |
| 1 | **clean-code** | Foundation | None | Naming, functions, structure, smell detection |
| 2 | **solid-principles** | Foundation | clean-code | Class design, contracts, dependency direction |
| 3 | **refactoring** | Transformation | clean-code | Safe structural changes, smell-to-technique mapping |
| 4 | **design-patterns** | Problem-solving | solid-principles | Pattern selection by intent, anti-pattern detection |
| 5 | **modern-python** | Language-specific | clean-code, solid-principles | Python 3.14+ idioms, type system, data modeling |
| 6 | **python-testing** | Language-specific | modern-python, refactoring | pytest mastery, async testing, mocking boundaries, property-based testing |
| 7 | **architecture-decisions** | Planning | solid-principles, design-patterns | ADR process, trade-off analysis, decision governance |
| 8 | **ddd-planning** | Planning | architecture-decisions | Domain discovery, Event Storming, strategic/tactical design planning |
| 9 | **domain-driven-design** | Enforcement | ddd-planning, solid-principles | DDD implementation, layers, infrastructure isolation |

## Two Learning Tracks

**Track A — General Software Engineering (skills 1-6):**
Start here if you want to write better code in any language/framework. Skills 1-4 are language-agnostic. Skills 5-6 apply them to Python specifically (idioms, then testing).

**Track B — Domain-Driven Design (skills 7-9):**
Start here after Track A if you're building domain-complex applications. Skill 7 teaches decision documentation. Skill 8 teaches DDD project planning. Skill 9 enforces DDD implementation.

## How to Use These Skills

- **As a human reader:** Read in order. Each skill's Overview, Quick Reference table, and Key Concepts sections give you the essentials. Dive into phases for details.
- **As an AI agent:** Skills are loaded on demand based on the task. Each skill is self-contained with its own gates and verification checks.
- **As a team onboarding guide:** Have new team members read skills 1-4, then the skills relevant to your project's domain and stack.

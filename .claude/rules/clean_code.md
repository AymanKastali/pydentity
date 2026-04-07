# Clean Code Standards & Architectural Manifesto

This document defines the architectural and stylistic requirements for all code generated or modified in this project. All contributions must adhere to these heuristics to ensure the system remains easy to evolve and "read like a book."

---

## 1. The Narrative Rule: Code as Prose

Code must be written to be read by developers as if they are reading English prose. A developer should understand the "story" of a process by reading high-level functions without needing to deep-dive into implementation details.

* **Declarative Orchestration:** High-level functions should describe **what** is happening, not **how**.
* **Small, Composable Verbs:** Extract logic into functions that act as clear verbs.
    * *Bad:* `if user.status == 1 and user.age > 18 and state == "NY":`
    * *Good:* `if user.is_eligible_for_regional_discount():`
* **The Stepdown Rule:** Every function should be immediately followed by the functions it calls — the next level of abstraction. You read code top-down like a set of **TO paragraphs**, never scrolling back up:
    * Three levels: **High** (business intent), **Mid** (coordination and guards), **Low** (mechanical state changes).
    * High → Mid → Low, always downward in the file. Never group by category (all guards together, all transitions together). Each public method is followed by the private methods it calls.
    * Shared helpers (used by multiple callers) are placed after their **first caller**.
* **Avoid "Code Stutter":** Do not repeat the class name in its methods. `account.deposit()` is prose; `account.account_deposit()` is redundant noise.

---

## 2. Universal Architectural Principles (SOLID)

Adhere to these five pillars to minimize technical debt and maximize extensibility:

* **Single Responsibility (SRP):** A module, class, or function must have **one** reason to change. If a class manages both database persistence and business logic, split it.
* **Open/Closed (OCP):** Software entities should be open for extension but closed for modification. Use Protocols/Interfaces to swap behaviors without touching core logic.
* **Liskov Substitution (LSP):** Subtypes must be completely interchangeable with their base types. Never "narrow" a precondition or "widen" a postcondition in a subclass.
* **Interface Segregation (ISP):** Prefer many small, specific interfaces over one "fat" interface. No class should be forced to implement methods it doesn't use.
* **Dependency Inversion (DIP):** Depend on abstractions, not concretions. High-level business logic should never depend on low-level infrastructure (e.g., a specific database driver).

---

## 3. Functions: The Atomic Units

* **15-Line Limit:** If a function exceeds 15 lines, it is likely doing too much. Extract sub-steps into private helpers.
* **Single Level of Abstraction (SLA):** Do not mix high-level orchestration with low-level details (like regex or math) in the same function.
* **Command/Query Separation (CQS):** Enforced across the entire domain layer.
    * **Commands:** Change state and return `None`.
    * **Queries:** Return data and are side-effect free (idempotent).
    * A method must never do both — if it changes state, it returns `None`; if it returns data, it must not mutate anything.
    * This is **method-level CQS only** — not CQRS (no separate read/write models, no separate query/command handlers).
* **Early Returns:** Favor guard clauses at the top of functions over deeply nested `if/else` structures.
* **No Flag Arguments:** Passing a `bool` to change a function's behavior is a code smell. Use two distinct functions instead.

---

## 4. Object-Oriented Mastery (OOP)

* **Composition Over Inheritance:** Prefer building complex behavior by combining simple objects. Use inheritance only for "is-a" relationships with shared behavior.
* **Tell, Don't Ask:** Do not fetch an object's data to perform logic on it. Tell the object what to do with its own data.
* **Law of Demeter:** An object should only talk to its "immediate friends." Avoid "train wrecks": `user.get_account().get_balance().is_overdrawn()`.
* **Value Objects:** Wrap primitive types in meaningful classes (e.g., `EmailAddress`, `Money`, `Currency`) to prevent "Primitive Obsession."
* **Immutability:** Use `frozen=True, slots=True` for dataclasses by default. Immutable state is significantly easier to debug and test.

---

## 5. Naming & Readability

* **Intention-Revealing Names:** Names should describe **why** something exists and **what** it does. If it needs a comment to explain, the name is a failure.
* **Booleans:** Always prefix with `is_`, `has_`, `can_`, or `should_`.
* **Searchable Names:** No single-letter variables (e.g., `i`, `j`) unless they are restricted to a 1-2 line loop scope.

---

## 6. Python 3.14+ Standards

* **Strict Typing:** Type-hint everything. Use PEP 695 generics and native unions (`|`). Avoid `Any` at all costs.
* **Built-ins First:** Leverage `any()`, `all()`, `zip()`, and `enumerate()` before writing manual loops.
* **Pattern Matching:** Use `match/case` for branching logic involving three or more conditions or complex object shapes.
* **Async Hygiene:** Use `asyncio.TaskGroup` for structured concurrency. Never call synchronous I/O inside an `async` function.

---

## 7. Error Handling & Resilience

* **Domain Exceptions:** Create specific exceptions (e.g., `InsufficientFundsError`) instead of using generic ones.
* **The Golden Path:** Keep the successful logic flow at the lowest indentation level.
* **Raise Early, Catch Late:** Validate at the boundary; handle errors at the top level of the call stack (e.g., the API controller).

---

## 8. Simplicity & Maintenance

* **YAGNI (You Ain't Gonna Need It):** Do not build for hypothetical future requirements.
* **DRY (Rule of Three):** Extract shared logic only after the third instance of duplication.
* **Delete Dead Code:** Unused code is a liability. Delete it.
* **The Boy Scout Rule:** Always leave the code slightly cleaner than you found it.

# Python Rules

Project-wide Python conventions enforced across all code. These complement `clean_code.md` with Python-specific requirements.

---

## 1. Classes & Inheritance

* **No `@staticmethod`:** Always use `@classmethod`. Static methods have no access to the class and cannot be overridden meaningfully.
* **ABC over Protocol:** Use `ABC` + `@abstractmethod` by default. Use `Protocol` only when structural subtyping is genuinely needed (e.g., third-party types you cannot modify).
* **PEP 695 Generics:** Use modern syntax (`class Foo[T]:`) exclusively. Never use `TypeVar`.

---

## 2. Imports & Style

* **UUID Import:** Always `from uuid import UUID`. Never `import uuid` followed by `uuid.UUID`.
* **No `from __future__ import annotations`:** Python 3.14+ has PEP 649 (lazy annotation evaluation) natively. This import is unnecessary and must not be used.
* **No Suppressions:** Never use `# noqa`, `# type: ignore`, or any other suppression directive. Fix the root cause.

---

## 3. Data Structures

* **Immutable Dataclasses:** Always use `frozen=True, slots=True` on all dataclasses (value objects and domain events).
* **Entities and Aggregates:** Normal classes. No `__slots__`.
* **Enum Types:** Use `StrEnum` with `auto()` when values are strings, `IntEnum` with `auto()` when values are integers, and `Enum` with `auto()` otherwise. Never use literal enum values.

---

## 4. Naming

* **Descriptive Variables:** Every variable, parameter, and loop variable must convey its purpose. Never abbreviate for brevity. `credential` not `c`, `account` not `acc`, `password_hash` not `ph`.
* **Domain Event Language:** Domain events are *recorded*, not *raised*. Use `_record_event()` — "raise" is reserved for exceptions in Python.

---

## 5. Typing

* **Annotate Everything:** Every function parameter, return type, variable assignment, and class attribute must have a type annotation. No exceptions.
    * Function signatures: all parameters and return type (`-> None` included).
    * Local variables: annotate when the type is not obvious from the right-hand side.
    * Instance variables: always annotate in `__init__`. `self._x: Type = x`, never `self._x = x`.
    * Class attributes: annotate as class-level declarations.
    * *Bad:* `def process(data, flag=True):` / `self._repo = repo` / `result = get_items()`
    * *Good:* `def process(data: AccountData, flag: bool = True) -> Result:` / `self._repo: AccountRepository = repo` / `result: list[Item] = get_items()`
* **PEP 695 & Native Unions:** Use modern generics (`class Foo[T]:`) and native unions (`X | Y`). Never use `TypeVar` or `Union`.
* **No `Any`:** Avoid `Any` at all costs. If the type is truly unknown, narrow it or redesign.
* **TYPE_CHECKING Guard:** Place imports used only for type hints inside `if TYPE_CHECKING:` blocks to avoid circular imports and runtime overhead.

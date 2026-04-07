# Refactoring Rules (Martin Fowler)

This document defines the refactoring standards for the project, based on Martin Fowler's *Refactoring: Improving the Design of Existing Code*.

---

## 1. The Refactoring Discipline

Refactoring is the process of restructuring existing code **without changing its external behavior**. It improves internal structure while keeping functionality identical.

* **Small Steps:** Apply one behavior-preserving transformation at a time. Never combine multiple refactorings into a single change.
* **Tests Gate Every Step:** Tests must pass after every individual refactoring. If they break, undo immediately and take a smaller step.
* **Commit After Each Refactoring:** Each successful refactoring gets its own commit. This gives you a safe rollback point.
* **Never Mix Refactoring with Behavior Changes:** A commit either refactors existing code or adds/changes behavior — never both. Mixing the two makes it impossible to verify that the refactoring preserved behavior.

---

## 2. When to Refactor

Refactoring is not a scheduled activity — it is woven into the daily workflow. Fowler identifies four modes:

* **Preparatory Refactoring:** Before adding a feature, refactor to make the upcoming change easy. *"It's like I want to go 100 miles east but instead of just traipsing through the woods, I'm going to drive 20 miles north to the highway, and then I'm going to go 100 miles east at three times the speed."* — Jessica Kerr, paraphrasing Kent Beck
* **Comprehension Refactoring:** When you read code and struggle to understand it, refactor it until it makes sense. The understanding you gain should live in the code, not in your head.
* **Litter-Pickup Refactoring:** When you see something slightly wrong while working on something else, fix it if it's quick. If not, note it and move on.
* **Planned Refactoring:** A dedicated effort to clean up accumulated debt. This should be rare — it means the first three modes were neglected.

---

## 3. Code Smells

Code smells are surface indicators of deeper structural problems. They signal where refactoring is needed.

### Bloaters
Smells that indicate code has grown too large:

* **Long Method** — A method doing too much. Extract smaller methods with intention-revealing names.
* **Large Class** — A class with too many responsibilities. Extract classes along cohesive lines.
* **Long Parameter List** — More than 2-3 parameters. Introduce a Parameter Object or use the calling object's existing data.
* **Primitive Obsession** — Using primitives (`str`, `int`) where a Value Object would add meaning and safety.
* **Data Clumps** — Groups of data that always appear together. Extract them into their own object.

### Object-Orientation Abusers
Smells that indicate incomplete or incorrect use of OOP:

* **Switch Statements** — Repeated conditionals on the same type discriminator. Replace with polymorphism.
* **Refused Bequest** — A subclass that ignores or overrides most of its parent's behavior. The hierarchy is wrong — use composition instead.
* **Temporary Field** — A field that is only set in certain circumstances. Extract the field and its behavior into a separate class.

### Change Preventers
Smells that make the codebase resist change:

* **Divergent Change** — One class that changes for many different reasons. Split it so each resulting class has a single reason to change (SRP).
* **Shotgun Surgery** — One change requires editing many classes. Move related behavior into a single class.
* **Parallel Inheritance Hierarchies** — Every time you add a subclass to one hierarchy, you must add one to another. Merge the hierarchies or use composition.

### Dispensables
Smells that indicate something unnecessary:

* **Lazy Class** — A class that doesn't do enough to justify its existence. Inline it.
* **Speculative Generality** — Abstractions built for hypothetical future needs. Delete them (YAGNI).
* **Dead Code** — Code that is never executed. Delete it — version control remembers.
* **Duplicate Code** — The same structure in more than two places. Extract and reuse.
* **Data Class** — A class with only fields and getters/setters but no behavior. Move behavior into it (Tell, Don't Ask).

### Couplers
Smells that indicate excessive coupling between classes:

* **Feature Envy** — A method that uses another class's data more than its own. Move it to the class it envies.
* **Inappropriate Intimacy** — Two classes that dig into each other's private details. Separate them or extract shared logic.
* **Message Chains** — A long chain of calls: `a.b().c().d()`. Hide the chain behind a delegate method (Law of Demeter).
* **Middle Man** — A class that delegates almost everything. Inline it or call the delegate directly.

---

## 4. Key Refactoring Techniques

The most important refactorings from Fowler's catalog:

### Composing Methods
* **Extract Method** — Turn a code fragment into a method whose name explains its purpose.
* **Inline Method** — Replace a method call with the method's body when the body is as clear as the name.
* **Replace Temp with Query** — Replace a temporary variable with a method call to make the logic reusable and visible.

### Moving Features Between Objects
* **Move Method** — Move a method to the class that uses its data most.
* **Move Field** — Move a field to the class that uses it most.
* **Extract Class** — Split a class that does two things into two classes that each do one thing.
* **Inline Class** — Merge a class that does too little back into its user.

### Organizing Data
* **Encapsulate Field** — Make a public field private and provide accessors.
* **Encapsulate Collection** — Return a read-only view of a collection, never the mutable original.
* **Replace Magic Number with Symbolic Constant** — Replace literals with named constants that explain intent.
* **Introduce Parameter Object** — Replace a recurring group of parameters with a single object.

### Simplifying Conditional Expressions
* **Decompose Conditional** — Extract the condition and each branch into methods with intention-revealing names.
* **Consolidate Conditional Expression** — Combine multiple conditions that lead to the same result into a single check with a descriptive name.
* **Replace Conditional with Polymorphism** — Replace type-checking conditionals with polymorphic method dispatch.

### Simplifying Method Calls
* **Rename Method** — Change a method's name to reveal its intention.
* **Replace Parameter with Method Call** — If a parameter can be obtained by calling a method the receiver already knows about, remove the parameter.

---

## 5. Refactoring Boundaries

Rules about when **not** to refactor:

* **No Tests, No Refactoring:** Do not refactor code that lacks test coverage. Write the tests first — they are your safety net.
* **Don't Refactor Across Published APIs:** Changing a published interface affects all consumers. Version it or deprecate gracefully instead.
* **Don't Refactor Under Deadline Pressure:** If a deadline is imminent, accept the technical debt consciously and record it. Refactoring under pressure leads to mistakes.
* **Don't Refactor and Add Features Simultaneously:** Separate the two activities. Refactor first, commit, then build the new feature on the cleaner foundation.

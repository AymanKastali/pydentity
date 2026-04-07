# Deep Dive into Domain-Driven Design

## The Foundation: Why DDD Exists

DDD exists to solve one problem — **complexity in the heart of software**. When the business rules are tangled, when teams talk past each other, when the model in your head doesn't match the model in the code, DDD gives you a disciplined way to align them. It operates on two levels: **Strategic Design** (the big picture) and **Tactical Design** (the building blocks).

---

## Part 1: Strategic Design

Strategic design is where the real power of DDD lives. Most teams skip this and pay for it later. This is about understanding the problem space before you touch the solution space.

### Ubiquitous Language

This is the single most important concept in all of DDD. It is a shared, rigorous language between developers and domain experts that is used in conversation, documentation, and code alike.

It's not a glossary you write and forget. It's a living language that evolves as understanding deepens. If a domain expert says "Policy" and a developer writes `Contract` in the model, something is broken. The language must be consistent everywhere — no translation layer between humans and the model.

Every bounded context has its **own** ubiquitous language. The word "Account" in the Banking context means something completely different from "Account" in the Identity context. This is not a bug — it's a feature.

### Bounded Context

A Bounded Context is an explicit boundary within which a particular model is defined and applicable. Inside a bounded context, every term has exactly one meaning, every model is internally consistent, and the ubiquitous language is unambiguous.

Think of it as a linguistic and conceptual boundary. The moment you find that a term means two different things to two groups of people, you've likely found the border between two bounded contexts.

A bounded context is **not** a module, not a service, not a layer. It's a boundary of meaning. How you deploy it is a separate decision.

### Subdomains

The problem space is divided into subdomains. These come in three types:

- **Core Domain** — The thing that gives the business its competitive advantage. This is where you invest your best people and deepest modeling effort. If this is wrong, the business fails.
- **Supporting Subdomain** — Necessary for the business to function but not a differentiator. It supports the core domain. It still needs custom modeling but doesn't need the same level of investment.
- **Generic Subdomain** — Solved problems. Authentication, email sending, scheduling. These are not unique to your business and can often be handled with existing solutions.

The critical insight: **you cannot and should not apply the same level of DDD rigor everywhere.** Pour your energy into the core domain. Let generic subdomains be simple.

### Context Mapping

Once you've identified your bounded contexts, you need to understand how they relate to each other. This is **Context Mapping**. The relationships between bounded contexts follow specific patterns:

- **Partnership** — Two teams in two contexts cooperate closely. They succeed or fail together. Changes are coordinated.
- **Shared Kernel** — Two contexts share a small, explicitly defined subset of the model. Both teams must agree on changes to the shared part. This creates coupling, so keep the kernel small.
- **Customer-Supplier** — One context (supplier/upstream) provides something that another context (customer/downstream) needs. The downstream team can make requests, and the upstream team accommodates them to some degree.
- **Conformist** — Like customer-supplier, but the downstream team has no influence over the upstream model. You just conform to whatever they give you.
- **Anticorruption Layer (ACL)** — A translation layer that the downstream context builds to protect its own model from being polluted by an upstream model. This is one of the most important defensive patterns in DDD. When an external or legacy model is messy, the ACL translates it into your clean domain language.
- **Open Host Service** — The upstream context provides a well-defined protocol or interface for others to consume. It's a deliberate, public-facing contract.
- **Published Language** — A well-documented, shared language (often combined with Open Host Service) that multiple consumers can use to integrate.
- **Separate Ways** — Two contexts have no integration at all. They solve their problems independently. Sometimes the best relationship is no relationship.

### The Problem Space vs. The Solution Space

DDD makes a sharp distinction here. The **problem space** is about understanding the business — its subdomains, processes, rules, and language. The **solution space** is about how you model and implement it — your bounded contexts, aggregates, and domain events.

Subdomains belong to the problem space. Bounded contexts belong to the solution space. They often align one-to-one, but not always.

---

## Part 2: Tactical Design

Tactical design gives you the building blocks to model the domain inside a bounded context. These patterns only make sense within a bounded context and should be used in your core domain. Don't over-engineer supporting or generic subdomains with these patterns unless warranted.

### Entities

An Entity is an object defined by its **identity**, not its attributes. Two entities with the same attributes but different identities are different objects. A person named "Ahmed" and another person named "Ahmed" are different entities because their identity (say, an ID number) differs.

Entities have a lifecycle. They are created, they change over time, and they may be archived or removed. Their identity remains continuous throughout.

### Value Objects

A Value Object is defined entirely by its **attributes**, not by an identity. Two value objects with the same attributes are interchangeable — they are equal.

Value objects should be **immutable**. Instead of changing a value object, you create a new one. An address, a monetary amount, a date range, a color — these are all natural value objects.

Value objects are one of the most underused patterns. When developers default to entities for everything, the model becomes bloated with unnecessary identity tracking. Favor value objects wherever identity doesn't matter.

### Aggregates

This is the most critical tactical pattern and the most misunderstood.

An **Aggregate** is a cluster of entities and value objects that are treated as a single unit for the purpose of data changes. Every aggregate has an **Aggregate Root** — the single entity through which all external access to the aggregate happens.

Key rules of aggregates:

- **External objects can only hold references to the aggregate root**, never to internal entities or value objects.
- **All invariants (business rules) within the aggregate boundary must be consistent after every transaction.** The aggregate is the transactional consistency boundary.
- **Aggregates should be small.** A common mistake is making aggregates too large. Every entity you add to an aggregate is another entity that must be loaded and locked when any change happens. Prefer smaller aggregates with eventual consistency between them over one massive aggregate.
- **Aggregates reference other aggregates by identity only**, not by direct object reference. This keeps aggregates decoupled and independently loadable.

Designing aggregate boundaries is the hardest modeling decision in DDD. Ask yourself: "What must be immediately consistent?" That's your aggregate. Everything else can be eventually consistent.

### Domain Events

A Domain Event represents **something meaningful that happened in the domain**. "Order Was Placed," "Payment Was Received," "Shipment Was Delayed" — these are things domain experts care about and talk about.

Domain events are named in past tense because they represent facts — things that already happened. They are immutable.

Domain events serve two major purposes. First, they communicate what happened within a bounded context so that other parts of the system can react. Second, they communicate across bounded context boundaries, enabling loose coupling between contexts.

Domain events are often the output of an aggregate processing a command. A command says "do this," the aggregate either rejects it or processes it and emits events saying "this happened."

### Repositories

A Repository provides the illusion of an in-memory collection of aggregates. It is the gateway through which you retrieve and persist aggregate roots.

A repository exists per aggregate root. You don't have a repository for internal entities within an aggregate — you go through the aggregate root.

The critical idea: the domain model defines the **interface** of the repository (what it needs — "give me an Order by its ID"), but the implementation of how that actually happens lives outside the domain.

### Domain Services

Sometimes a business operation doesn't naturally belong to any single entity or value object. When an operation involves multiple aggregates or doesn't conceptually fit as a behavior of any one object, it belongs in a **Domain Service**.

Domain services are stateless. They express domain logic that operates across objects. "Transfer money between two accounts" doesn't belong to either account — it belongs to a domain service like a Transfer Service.

Be careful: domain services are overused when developers are uncomfortable putting behavior on entities and value objects. The default should be to put logic on the objects themselves. Reach for a domain service only when the operation genuinely spans multiple objects.

### Factories

A Factory encapsulates the complex creation logic of aggregates or value objects. When constructing an object requires intricate setup, validation, or assembly, a factory handles that responsibility and keeps it out of the object itself.

Factories ensure that aggregates are born in a valid state, with all invariants satisfied from the moment of creation.

### Modules

Modules are a way of organizing your model into cohesive, low-coupling groupings within a bounded context. They reflect meaningful divisions in the ubiquitous language — not technical layers. A module should tell a story about the domain when you look at it.

---

## Part 3: Patterns That Tie It Together

### Event Storming

A collaborative discovery technique where domain experts and developers explore the domain by placing **Domain Events** on a timeline, then discovering the **Commands** that cause them, the **Aggregates** that process them, the **Policies** that react to them, and the **Read Models** that users need to make decisions.

This is the most practical way to go from "we have a domain" to "we have a model." It works at both the strategic level (discovering bounded contexts and subdomains) and the tactical level (discovering aggregates and events).

### Specification

A Specification encapsulates a business rule as a named, composable object. Instead of scattering conditional logic throughout the model, you express it as a Specification that can be combined (AND, OR, NOT) and reused. "Is this customer eligible for a premium discount?" becomes a named, testable object.

### Intention-Revealing Interfaces

Every element of the model — every method, every object — should declare its purpose through its name without exposing how it works. The interface should express **what** it does in domain terms, not **how** it does it.

### Side-Effect-Free Functions

Where possible, domain logic should be expressed as functions that return results without modifying state. This makes the model easier to understand, test, and compose. Value objects naturally support this since they're immutable.

### Closure of Operations

When an operation takes an input and returns an output of the same type, it's said to have closure. Value objects are prime candidates — adding two Money value objects returns a Money value object. This makes the model composable and predictable.

### Assertions

Aggregates and entities should make their rules explicit through clearly stated pre-conditions, post-conditions, and invariants. These are not hidden — they are part of the model's contract and part of the ubiquitous language.

---

## Part 4: The Modeling Mindset

DDD is not a recipe — it's a mindset. Some principles to internalize:

**Model exploration is iterative.** Your first model will be wrong. Your second will be better. Your tenth will be good. The model is a living thing that evolves with your understanding of the domain. Refactor toward deeper insight relentlessly.

**Knowledge crunching is continuous.** You never stop learning the domain. Every conversation with a domain expert, every edge case discovered in production, every ambiguity resolved — these are opportunities to deepen the model.

**Supple design matters.** A good domain model is not just correct — it's easy to work with, easy to extend, and easy to reason about. The tactical patterns above (intention-revealing interfaces, side-effect-free functions, closure of operations) all serve this goal.

**The model is the code, and the code is the model.** There should be no gap. If you draw a model on a whiteboard and the code doesn't mirror it, one of them is wrong — and it's usually the code.

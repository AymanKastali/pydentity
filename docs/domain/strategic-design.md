# Strategic Design

DDD strategic design for the pydentity identity management system.

---

## Domain Vision Statement

**Core Domain:** Authentication

**What It Is:** pydentity is an identity management system whose core value lies in its Authentication context — account lifecycle management, credential security (NIST 800-63B compliant breach-checking, password history enforcement), lockout protection, multi-device session handling, and time-limited verification flows. The domain model encodes security invariants directly as business rules on Aggregates, ensuring correctness by construction rather than by convention.

**Why It Matters:** Authentication is the reason this system exists. Secure identity management with rich domain rules — password breach checking, account lockout thresholds, device limits, token expiration, verification request invalidation — is the competitive differentiator. These rules are too complex and too critical for anemic models or ad-hoc validation. They require a domain model that enforces them as first-class invariants.

**What It Is NOT:** Audit logging and notification delivery are necessary but not differentiating. Audit is an append-only record of what happened — it has no business rules beyond immutability. Notification is a delivery mechanism — it decides how to send messages, not what the business means. Neither justifies Core Domain investment.

**Success Metric:** The domain model correctly enforces all security invariants (password breach checking, lockout thresholds, device limits, token expiration, verification state machines) without infrastructure leakage — every invariant is testable with zero infrastructure dependencies.

---

## Subdomains

| Subdomain | Type | Responsibility |
|-----------|------|----------------|
| Authentication | Core | Account lifecycle, credential management, session handling, device tracking, verification flows. The primary business differentiator. |
| Audit | Supporting | Immutable recording of domain events for compliance, traceability, and observability. |
| Notification | Supporting | Message delivery to users across channels (email, SMS) with retry and sensitive content handling. |

---

## Bounded Contexts

### Authentication (Core)

The central context of the system. Owns all identity and access concepts.

**Aggregates:** Account, Session, Device, VerificationRequest

**Boundary evidence:**
- *Language boundary:* Credentials, sessions, devices, and verification requests form a cohesive vocabulary that does not overlap with audit or notification terminology.
- *Consistency boundary:* Account status, failed attempt count, and lockout must be transactionally consistent. Password history, device limits, and verification request invalidation require immediate consistency within the aggregate.
- *Domain expert ownership:* All concepts are owned by a single area of expertise — identity and access management.

**Key responsibilities:**
- Account registration with email/password credentials
- Authentication with lockout protection
- Email verification and password reset flows
- Session lifecycle (start, refresh, end, forced termination)
- Device registration with fingerprint hashing and limit enforcement
- Verification request creation, token verification, invalidation, and expiration

**Domain rules enforced:**
- Passwords checked against breach databases (NIST 800-63B)
- Password history prevents reuse
- Account locks after failed attempt threshold
- Maximum active devices per account
- Pending verification requests invalidated when new ones are created
- Verification tokens are time-limited

### Audit (Supporting)

Downstream consumer of domain events. Records what happened and to whom.

**Aggregates:** AuditEntry

**Boundary evidence:**
- *Language boundary:* Audit speaks in entries, event names, and payloads — a different vocabulary from credentials, sessions, or devices.
- *Data model divergence:* Append-only, generic key-value payloads. Fundamentally different lifecycle from Authentication's mutable aggregates.
- *No shared invariants:* AuditEntry has no transactional relationship with any Authentication aggregate.

**Key responsibilities:**
- Record immutable audit entries from domain events
- Provide query access by account and event name

**Characteristics:**
- Append-only (no update or delete operations)
- No domain events of its own (the audit entry IS the record)

### Notification (Supporting)

Downstream consumer of domain events. Delivers messages to users.

**Aggregates:** DeliveryRequest

**Boundary evidence:**
- *Language boundary:* Notification speaks in delivery requests, recipients, channels, and attempt counts — orthogonal to authentication vocabulary.
- *Independent lifecycle:* Delivery mechanics (retry logic, content purging, channel selection) are self-contained and change for different reasons than authentication rules.
- *No shared invariants:* DeliveryRequest has no transactional relationship with any Authentication aggregate.

**Key responsibilities:**
- Deliver messages via email or SMS
- Track delivery attempts and handle retries
- Purge sensitive content after successful delivery

**Characteristics:**
- Reacts to events from Authentication (e.g., account registered, verification requested)
- Manages its own delivery lifecycle independently

---

## Shared Kernel

Cross-cutting value objects shared by all bounded contexts.

| Value Object | Authentication | Audit | Notification |
|--------------|:-:|:-:|:-:|
| AccountId | x | x | x |
| DeviceId | x | | |
| EventName | | x | |

The shared kernel also defines the building block base types (ValueObject, DomainEvent, DomainError, Entity, AggregateRoot) that all contexts inherit from.

---

## Context Map

```
┌─────────────────────────────────────────────────────┐
│                   Shared Kernel                      │
│         AccountId, DeviceId, EventName                │
└──────────────┬──────────────────┬───────────────────┘
               │                  │
               │ SK               │ SK
               │                  │
┌──────────────▼──────────────────▼───────────────────┐
│                                                      │
│              Authentication (Core)                    │
│    Account · Session · Device · VerificationRequest  │
│                                                      │
└──────────┬──────────────────────┬───────────────────┘
           │                      │
           │ U/D                  │ U/D
           │ Published Language   │ Published Language
           │                      │
┌──────────▼─────────┐  ┌────────▼────────────────────┐
│                     │  │                              │
│  Audit (Supporting) │  │  Notification (Supporting)   │
│    AuditEntry       │  │    DeliveryRequest           │
│                     │  │                              │
└─────────────────────┘  └──────────────────────────────┘

SK  = Shared Kernel
U/D = Upstream / Downstream
PL  = Published Language
```

### Relationship Type Rationale

All inter-context relationships were evaluated against Evans' nine Context Map relationship types (Evans, DDD Ch. 14):

| Type | Applies? | Reason |
|------|:--------:|--------|
| Partnership | No | Contexts do not co-evolve — downstream contexts react independently to upstream events |
| Shared Kernel | **Yes** | AccountId, DeviceId, EventName are co-owned across contexts |
| Customer-Supplier | No | Downstream contexts have no influence over Authentication's event contracts |
| Conformist | No | Downstream contexts translate events into their own models, they do not adopt Authentication's model as-is |
| Anti-Corruption Layer | No | All contexts are internal and well-designed. Event translation happens naturally in application-layer event handlers — no defensive translation layer needed |
| Open Host Service | No | Authentication does not expose a documented API for consumers — integration is event-driven |
| Published Language | **Yes** | Domain Events serve as the shared contract between Authentication and its downstream consumers |
| Separate Ways | No | Audit and Notification both depend on Authentication events |
| Big Ball of Mud | No | No legacy systems involved |

### Authentication → Audit (Published Language)

| Aspect | Detail |
|--------|--------|
| Pattern | Published Language |
| Direction | Authentication (upstream) → Audit (downstream) |
| Integration | Domain events from Authentication are consumed by Audit to create AuditEntry records |
| Contract | EventName identifies the event type; EventPayload carries context as key-value pairs |
| Coupling | Loose — Audit subscribes to published events and translates them into its own domain model at the application layer |

**Events consumed by Audit:**
AccountRegistered, LoginSucceeded, LoginFailed, EmailVerified, EmailChanged, PasswordChanged, AccountLocked, AccountUnlocked, AccountSuspended, AccountClosed, SessionStarted, SessionEnded, DeviceRegistered, DeviceRevoked, VerificationRequestCreated, VerificationRequestVerified, VerificationRequestFailed, VerificationRequestInvalidated, VerificationRequestExpired

### Authentication → Notification (Published Language)

| Aspect | Detail |
|--------|--------|
| Pattern | Published Language |
| Direction | Authentication (upstream) → Notification (downstream) |
| Integration | Domain events from Authentication trigger DeliveryRequest creation in Notification |
| Contract | Notification translates Authentication events into delivery requests with appropriate channel, recipient, content, and sensitivity |
| Coupling | Loose — Notification decides what to send and how; Authentication has no knowledge of delivery mechanics |

**Events that trigger notifications:**

| Event | Notification |
|-------|-------------|
| AccountRegistered | Welcome email |
| VerificationRequestCreated (EMAIL_VERIFICATION) | Email verification link (sensitive) |
| VerificationRequestCreated (PASSWORD_RESET) | Password reset link (sensitive) |
| PasswordChanged | Password change confirmation |
| AccountLocked | Account locked alert |
| AccountClosed | Account closure confirmation |
| DeviceRegistered | New device alert |

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Authentication as a single bounded context | Account, Session, Device, and VerificationRequest are tightly coupled through AccountId and share authentication workflows. Splitting would create excessive cross-context communication. |
| Separate Audit context | Audit has a fundamentally different data model (append-only, generic payload) and lifecycle. It should not be coupled to Authentication's internal structure. |
| Separate Notification context | Delivery mechanics (channels, retries, content purging) are independent of what triggered the notification. Notification owns its own delivery lifecycle. |
| Shared Kernel for IDs | AccountId appears in all three contexts. A shared kernel avoids mapping layers for simple identity references while keeping the coupling minimal. |
| Event-driven integration | Downstream contexts react to published events rather than being called directly. This keeps Authentication unaware of its consumers and allows new consumers to be added without modifying the core. |
| No Anti-Corruption Layer | All three contexts are internal and well-designed. Event translation happens naturally in application-layer event handlers. ACL would add unnecessary indirection. |
| Large-Scale Structure: Evolving Order | The system has 3 Bounded Contexts — structure will emerge as the system grows. No imposed large-scale structure (Responsibility Layers, Knowledge Level, etc.) is needed at this scale. (Evans, DDD Ch. 16) |

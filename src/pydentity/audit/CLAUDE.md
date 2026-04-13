# Audit Context (Supporting Subdomain)

Immutable recording of security-relevant domain events for compliance, traceability, and observability. Append-only — no updates, no deletes.

---

## Aggregate: AuditEntry

**Identity:** `AuditEntryId` (UUID)
**References by ID:** `AccountId`

**Immutable after creation.** The `record` factory method is the only way to create an entry. No mutation methods exist.

**State:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | `AuditEntryId` | Unique entry identifier |
| `event_name` | `EventName` | Name of the audited domain event |
| `account_id` | `AccountId` | Account associated with the event |
| `payload` | `EventPayload` | Key-value pairs with event context |

**Behavior:** `record(id, event_name, account_id, payload)` — static factory method, creates an immutable audit record.

---

## Value Objects

| Name | Fields | Constraints |
|------|--------|-------------|
| `AuditEntryId` | `value: UUID` | — |
| `EventPayload` | `entries: tuple[tuple[str, str], ...]` | Max 50 entries, key max 100 chars, value max 500 chars |

---

## Repository

All methods are async.

| Method | Description |
|--------|-------------|
| `save(entry)` | Persist audit entry |
| `find_by_id(entry_id) -> AuditEntry \| None` | Retrieve by identity |
| `find_by_account_id(account_id) -> list[AuditEntry]` | Query by account |
| `find_by_event_name(event_name) -> list[AuditEntry]` | Query by event type |

---

## Cross-Boundary Event Consumption

Audit is a **downstream conformist** consumer of Authentication. It subscribes to all Authentication domain events via Published Language and translates them into `AuditEntry` records at the application layer.

**Events consumed (19 from Authentication — `SessionRefreshed` is internal to Authentication, not cross-boundary):**

`AccountRegistered`, `LoginSucceeded`, `LoginFailed`, `EmailVerified`, `EmailChanged`, `PasswordChanged`, `AccountLocked`, `AccountUnlocked`, `AccountSuspended`, `AccountClosed`, `SessionStarted`, `SessionRevoked`, `DeviceRegistered`, `DeviceRevoked`, `VerificationRequestCreated`, `VerificationRequestVerified`, `VerificationRequestFailed`, `VerificationRequestInvalidated`, `VerificationRequestExpired`

**Events produced:** None. Audit is a terminal consumer.

---

## Rules

- **Immutability:** No update or delete operations. Once created, an audit entry never changes.
- **No PII in payload:** Payload must not contain email addresses, phone numbers, names, or personal data. Only identifiers and metadata. If an auditor needs PII, they look it up in the Authentication context using `AccountId`.
- **Append-only:** The repository has `save` but no `update` or `delete` methods.
- **EventPayload constraints:** Max 50 entries per payload, key max 100 characters, value max 500 characters — enforced via guards in `__post_init__`.

## References

- Design: `docs/domain/tactical-design.md` (Audit Context section)
- Strategic: `docs/domain/strategic-design.md`
- UML: `docs/diagrams/uml/audit/audit_entry.puml`
- Glossary: `docs/domain/ubiquitous-language.md` (Audit section)

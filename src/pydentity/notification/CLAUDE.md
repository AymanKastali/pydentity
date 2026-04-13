# Notification Context (Supporting Subdomain)

Message delivery to users across channels (email, SMS) with retry handling and sensitive content purging. A solved problem — minimal domain logic, do not over-engineer.

---

## Aggregate: DeliveryRequest

**Identity:** `DeliveryRequestId` (UUID)
**References by ID:** `AccountId`

**Status state machine:**

```
PENDING --> SENT     [mark_sent]
PENDING --> FAILED   [mark_failed]
```

**Key invariants:**
- Only `PENDING` can transition to `SENT` or `FAILED`
- Content is purged only for `SENSITIVE` deliveries and only after status is `SENT`
- Attempt count is monotonically increasing

**State:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | `DeliveryRequestId` | Unique request identifier |
| `account_id` | `AccountId` | Target account |
| `recipient` | `Recipient` | Delivery address |
| `channel` | `Channel` | Email or SMS |
| `content` | `MessageContent \| None` | Message subject and body. `None` after purging |
| `status` | `DeliveryStatus` | Current delivery state |
| `attempt_count` | `AttemptCount` | Number of delivery attempts |
| `sensitivity` | `ContentSensitivity` | Whether content must be purged after delivery |

**Behaviors:** `create`, `mark_sent`, `record_failed_attempt`, `mark_failed`, `purge_content`

---

## Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| `DeliveryRequestId` | `value: UUID` | Identifies a delivery request |
| `Recipient` | `address: str` | Delivery address (max 254 chars) |
| `MessageContent` | `subject: str \| None, body: str` | Message content (subject max 200 chars, body max 50,000 chars) |
| `AttemptCount` | `value: int` | Delivery attempt counter |

## Enums

| Name | Values | Purpose |
|------|--------|---------|
| `Channel` | `EMAIL`, `SMS` | Delivery method |
| `ContentSensitivity` | `SENSITIVE`, `STANDARD` | Whether content requires purging after delivery |
| `DeliveryStatus` | `PENDING`, `SENT`, `FAILED` | Delivery lifecycle |

---

## Repository

All methods are async.

| Method | Description |
|--------|-------------|
| `save(request)` | Persist delivery request |
| `find_by_id(request_id) -> DeliveryRequest \| None` | Retrieve by identity |
| `find_pending() -> list[DeliveryRequest]` | Retrieve all pending deliveries |
| `find_failed() -> list[DeliveryRequest]` | Retrieve all failed deliveries |
| `find_sensitive_requiring_purge() -> list[DeliveryRequest]` | Retrieve sent sensitive deliveries needing content purge |

---

## Cross-Boundary Event Consumption

Notification is a **downstream conformist** consumer of Authentication. Event-to-delivery mapping happens at the application layer — Notification translates Authentication events into `DeliveryRequest` records.

**Events that trigger delivery requests (7):**

| Authentication Event | Notification Action |
|---------------------|---------------------|
| `AccountRegistered` | Welcome email (`STANDARD`) |
| `VerificationRequestCreated` (EMAIL_VERIFICATION) | Email verification link (`SENSITIVE`) |
| `VerificationRequestCreated` (PASSWORD_RESET) | Password reset link (`SENSITIVE`) |
| `PasswordChanged` | Password change confirmation (`STANDARD`) |
| `AccountLocked` | Account locked alert (`STANDARD`) |
| `AccountClosed` | Account closure confirmation (`STANDARD`) |
| `DeviceRegistered` | New device alert (`STANDARD`) |

**Events produced (internal only):** `MessageDelivered`, `MessageDeliveryFailed`

**No feedback to Authentication.** If delivery fails, Authentication has no awareness. This is intentional — prevents bidirectional coupling.

---

## Rules

- **Sensitive content purging:** After successful delivery, `SENSITIVE` content must be purged from the database. Tokens, verification codes, and reset links must not persist.
- **No bidirectional coupling:** Notification never notifies Authentication of delivery success or failure. Consumers can query delivery status if needed.
- **Minimal domain logic:** This is a solved problem. Do not add complex business rules. The domain model is deliberately thin.
- **All repositories are async interfaces** (ABC with abstract async methods).

## References

- Design: `docs/domain/tactical-design.md` (Notification Context section)
- Strategic: `docs/domain/strategic-design.md`
- UML: `docs/diagrams/uml/notification/delivery_request.puml`
- Glossary: `docs/domain/ubiquitous-language.md` (Notification section)

# Authentication Service — Tactical Design: Audit & Notification

This file is the canonical source for the 30 Authentication domain events consumed by Audit (with payload details) and the 3 events consumed by Notification. Other rule files reference this file rather than duplicating these lists.

---

## 1. Design Approach

These two contexts are intentionally lightweight. They are not the core domain and do not warrant the same modeling depth as Authentication.

| Context | Subdomain Type | Approach |
|---------|---------------|----------|
| **Audit** | Supporting | One aggregate. Append-only. Focus is on queryability, not complex domain logic. |
| **Notification** | Generic | One aggregate. Minimal model. Solved problem. Focus is on reliable delivery, not domain richness. |

---

## 2. Audit Bounded Context (Supporting Subdomain)

**Core Question:** What happened and when?

**Relationship to Authentication:** Conformist. Audit subscribes to Authentication's domain events and adapts to its model.

---

### Aggregate: Audit Entry

**Aggregate Root:** Audit Entry (Entity)

**Immutability Rule:** Audit Entries are **append-only.** Once created, a record is never modified or deleted by application logic. This guarantees the integrity of the audit trail.

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Audit Entry** | Entity (Root) | An immutable record of a security-relevant event. |
| **Audit Entry ID** | Value Object | Unique identifier. |
| **Event Type** | String | The type of event. Maps directly to Authentication's domain events. |
| **Account ID** | Value Object | The Account involved in the event. |
| **Event Payload** | Value Object | Tuple of key-value pairs. Max 50 entries. Key max 100 characters. Value max 500 characters. See PII restrictions below. |

#### PII Restriction

**Event Payload must not contain Personally Identifiable Information (PII).** No raw email addresses, phone numbers, names, or other personal data. Payloads contain only **identifiers and metadata** (Account ID, Attempt ID, Session ID, Credential Type, Device Fingerprint, reason codes, factor types). If an auditor needs to see PII such as an email address, they look it up in the Authentication context using the Account ID. Audit does not duplicate PII.

| Allowed in Payload | Not Allowed in Payload |
|---|---|
| Account ID | Email Address |
| Session ID, Attempt ID | Phone Number |
| Credential Type (Password, TOTP, Recovery Code) | Raw Credential values |
| Device Fingerprint | Person's name |
| Factor type (Knowledge, Possession) | Any raw PII |
| Reason codes (manual, lockout, closure, expiration) | |

#### Behaviors

| Behavior | Description | Preconditions | Postconditions |
|----------|-------------|---------------|----------------|
| **Record Event** | Creates a new Audit Entry from an Authentication domain event. | Must receive a valid event with Identity ID and Account ID. | Record persisted. Immutable from this point forward. |

This is the **only write operation** in the entire Audit context. Everything else is read.

#### Events Consumed from Authentication (30 total)

| Event | Payload Details (identifiers and metadata only) |
|-------|----------------|
| Identity Created | Identity ID |
| Account Registered | Account ID, Identity ID |
| Email Verification Requested | Account ID |
| Email Verified | Account ID |
| Authentication Succeeded | Account ID, Attempt ID, factors used |
| Authentication Failed | Account ID, Attempt ID |
| Verification Code Generated | Account ID, Attempt ID |
| Account Locked | Account ID, reason (LockReason: THRESHOLD or ADMIN) |
| Account Unlocked | Account ID, reason (UnlockReason: EXPIRY or ADMIN) |
| Account Suspended | Account ID |
| Account Closed | Account ID |
| TOTP Secret Added | Account ID |
| TOTP Secret Removed | Account ID |
| Recovery Codes Generated | Account ID |
| Recovery Code Consumed | Account ID |
| Password Changed | Account ID |
| MFA Enabled | Account ID |
| MFA Disabled | Account ID |
| Password Reset Completed | Account ID |
| Session Started | Account ID, Session ID |
| Session Ended | Account ID, Session ID, reason (LOGOUT, IDLE_TIMEOUT, ABSOLUTE_TIMEOUT, FORCED, COMPROMISE) |
| Refresh Token Rotated | Account ID, Session ID |
| Password Reset Requested | Account ID, Recovery Request ID |
| Recovery Token Issued | Account ID, Recovery Request ID |
| Recovery Token Verified | Account ID, Recovery Request ID |
| Recovery Request Completed | Account ID, Recovery Request ID |
| Password Reset Expired | Account ID, Recovery Request ID |
| Device Trusted | Account ID, Device Fingerprint |
| Trusted Device Revoked | Account ID, Device Fingerprint, reason (MANUAL, ADMIN, LOCKOUT, CLOSURE, PASSWORD_CHANGED, MFA_RECONFIGURED, LIMIT_EXCEEDED) |
| Trusted Device Expired | Account ID, Device Fingerprint |

#### Domain Events Produced

Audit produces **no domain events.** It is a terminal consumer. Nothing downstream reacts to Audit.

---

### Repository: Audit Entry Repository

| Operation | Description |
|-----------|-------------|
| **Save** | Persists a new Audit Entry. Append-only. |
| **Find by Audit Entry ID** | Retrieves a single record. |
| **Query by Account ID** | All events for a given Account. |
| **Query by Event Type** | All events of a specific type. |

---

### Access Control

Audit queries are exposed to consumers via the Open Host Service. Because audit records contain security-sensitive metadata, the following access control principles apply:

| Principle | Description |
|-----------|-------------|
| **Consumer Scoping** | A consumer should only be able to query audit records for Accounts and Identities that were created through their integration. Cross-consumer visibility must be explicitly prevented. |
| **Sensitive Endpoint** | Audit query endpoints are high-value targets. They must be protected with strong authentication and appropriate rate limiting. |
| **Implementation Detail** | The specific access control mechanism (API key scoping, tenant isolation, attribute-based access control) is an infrastructure concern. The domain acknowledges the requirement; implementation lives outside the domain model. |

---

### Retention Policy

Retention Policy is a **system-wide configuration**, not part of the aggregate. It governs:

| Rule | Description |
|------|-------------|
| **Retention Period** | How long records are kept before archival or deletion (e.g., 90 days, 1 year, 7 years). |
| **Archival Strategy** | Whether expired records are deleted or moved to cold storage. |
| **Compliance Requirements** | Industry or regulatory requirements that dictate minimum retention (e.g., SOC 2, GDPR). |

Retention is enforced at the infrastructure level (scheduled cleanup jobs), not by the aggregate.

---

### Audit — Complete Summary

| Element | Count | Details |
|---------|-------|---------|
| Aggregates | 1 | Audit Entry |
| Value Objects | 4 | Audit Entry ID, Event Type (string), Account ID, Event Payload (tuple of key-value pairs, no PII) |
| Behaviors | 1 | Record Event (append-only) |
| Domain Events Produced | 0 | Audit is a terminal consumer |
| Events Consumed | 30 | All Authentication domain events |
| Repository | 1 | Audit Entry Repository |

---

---

## 3. Notification Bounded Context (Generic Subdomain)

**Core Question:** How do we deliver messages to people?

**Relationship to Authentication:** Conformist. Notification subscribes to Authentication's events that require message delivery and adapts to its model.

---

### Event-to-Delivery Mapping

Not every Authentication event requires a notification. Only the following events trigger message delivery:

| Authentication Event | Notification Action | Channel |
|---------------------|-------------------|---------|
| Email Verification Requested | Deliver the verification link to the person | Email |
| Verification Code Generated | Deliver the one-time Verification Code to the person | Email or SMS (as specified in event payload) |
| Recovery Token Issued | Deliver the raw Recovery Token to the person | Email |

All three events are defined in the Authentication bounded context and published by Authentication aggregates. Notification consumes them as a Conformist.

A **thin translation layer** sits between event subscription and Delivery Request creation. It maps Authentication events to human-readable messages using templates. This translation is not a domain concern — it's infrastructure.

---

### Aggregate: Delivery Request

**Aggregate Root:** Delivery Request (Entity)

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Delivery Request** | Entity (Root) | A request to deliver a message to a person. |
| **Request ID** | Value Object | Unique identifier. |
| **Account ID** | Value Object | Reference to the Account that triggered this delivery. |
| **Recipient** | Value Object | The destination address (email address, phone number). Max 254 characters. |
| **Channel** | Value Object | Enum: Email, SMS. The medium of delivery. |
| **MessageContent** | Value Object | The message content. Optional subject (max 200 chars) and required body (max 50,000 chars). |
| **Delivery Status** | Value Object | Enum: Pending, Sent, Failed. |
| **Attempt Count** | Integer | Number of delivery attempts made. Used with Retry Policy. |
| **Sensitive** | Boolean | Whether this Delivery Request contains sensitive content (Recovery Tokens, Verification Codes). Governs cleanup behavior. |

#### Behaviors

| Behavior | Description | Preconditions | Postconditions |
|----------|-------------|---------------|----------------|
| **Create** | Creates a new Delivery Request from an Authentication event via the translation layer. Marks as Sensitive if content contains tokens or codes. | Must have a valid Recipient, Channel, and MessageContent. | Status → Pending. Attempt Count → 0. Sensitive flag set. |
| **Mark Sent** | Records successful delivery. | Status must be Pending. | Status → Sent. Message Delivered event emitted. |
| **Record Failed Attempt** | Records a failed delivery attempt. Increments Attempt Count. | Status must be Pending. | Attempt Count incremented. Status remains Pending. |
| **Mark Failed** | Marks as permanently failed. | Status must be Pending. | Status → Failed. Message Delivery Failed event emitted. |
| **Purge Content** | Clears the MessageContent field after successful delivery. | Sensitive must be true. Content must not already be purged. | MessageContent field cleared. Record retained for delivery tracking but sensitive data is gone. |

#### Domain Events Produced

| Event | Trigger |
|-------|---------|
| Message Delivered | Send succeeds |
| Message Delivery Failed | Mark Failed (permanent failure after retries exhausted) |

These events are internal to Notification. They do not flow back to Authentication. Authentication does not know or care whether delivery succeeded — that's Notification's responsibility.

#### Domain Events Consumed

None directly. Delivery Requests are created by the translation layer reacting to Authentication events, not by consuming events within the aggregate.

---

### Repository: Delivery Request Repository

| Operation | Description |
|-----------|-------------|
| **Save** | Persists a new or updated Delivery Request. |
| **Find by Request ID** | Retrieves a single request. |
| **Find Pending** | All requests in Pending status (for processing). |
| **Find Failed** | All requests in Failed status (for retry or investigation). |
| **Find Sensitive Requiring Purge** | All Sensitive requests where Status is Sent and Content has not yet been purged (for cleanup). |

---

### Delivery Request Cleanup Policy

Delivery Requests containing sensitive content (Recovery Tokens, Verification Codes) must have their Content purged after delivery to prevent exposure in case of database compromise.

| Rule | Description |
|------|-------------|
| **Scope** | Applies to all Delivery Requests where Sensitive = true. |
| **Trigger** | Content is purged after successful delivery (Status = Sent) or after a short time window (e.g., 1 hour) regardless of delivery status. |
| **What Is Purged** | The Content field is cleared. The Delivery Request record itself is retained for delivery tracking and audit purposes (Request ID, Recipient, Channel, Status, timestamps). |
| **Rationale** | Authentication hashes all tokens and codes. If Notification stores the raw values in Content, a database breach would expose them. Purging eliminates this risk. |
| **Enforcement** | Handled by a scheduled infrastructure job, not by the aggregate. The Purge Content behavior is the domain operation; when and how often it runs is infrastructure. |

---

### Retry Policy

Retry Policy is a **system-wide configuration**, not part of the aggregate. It governs:

| Rule | Description |
|------|-------------|
| **Max Retries** | Maximum number of delivery attempts before permanent failure (e.g., 3). |
| **Retry Interval** | Time between retry attempts (e.g., exponential backoff: 1 min, 5 min, 15 min). |
| **Channel Fallback** | Whether to try an alternative channel after primary channel failure (e.g., fall back from SMS to Email). Policy decision. |

---

### Templates

Templates are an **infrastructure concern**, not a domain concept. They govern:

| Aspect | Description |
|--------|-------------|
| **Purpose** | Transform Authentication event data into human-readable messages. |
| **Ownership** | Managed outside the Notification domain model. Could be files, database records, or configuration. |
| **Per-Channel Formatting** | Email templates include subject lines and HTML/text body. SMS templates are plain text with character limits. |
| **Localization** | If the service supports multiple languages, templates handle translation. Notification's domain model doesn't care about language — it receives Content already translated. |

---

### Known Trade-Off: No Delivery Failure Feedback to Authentication

Authentication publishes events and does not know Notification exists (Conformist relationship). If Notification permanently fails to deliver a Recovery Token or Verification Code, Authentication has no awareness of the delivery failure. The person is stuck — they requested a password reset but the email never arrived, and Authentication doesn't know.

**This is intentional.** Introducing feedback from Notification to Authentication would create a bidirectional dependency that violates the Conformist relationship and couples the Core Domain to a Generic Subdomain.

**Mitigation:** Consumers can query Notification's Delivery Request status via the Open Host Service to investigate delivery failures. "Why didn't the person receive their reset email?" is answered by checking the Delivery Request for that Recovery Token Issued event — its status (Sent, Failed), attempt count, and failure reason. This is an operational concern, not a domain modeling change.

---

### Notification — Complete Summary

| Element | Count | Details |
|---------|-------|---------|
| Aggregates | 1 | Delivery Request |
| Value Objects | 6 | Delivery Request ID, Account ID, Recipient, Channel, MessageContent, Delivery Status |
| Behaviors | 5 | Create, Mark Sent, Record Failed Attempt, Mark Failed, Purge Content |
| Domain Events Produced | 2 | Message Delivered, Message Delivery Failed (internal only) |
| Events Triggering Delivery | 3 | Email Verification Requested, Verification Code Generated, Recovery Token Issued |
| Repository | 1 | Delivery Request Repository |

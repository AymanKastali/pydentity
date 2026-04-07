# Authentication Service — Strategic Design

## 1. Service Boundary

This is a **standalone authentication service** consumed by external systems. It answers one question: **"Are you who you claim to be?"**

The service does not own Authorization, User Profile, or any consumer-side concerns. It provides a contract that consumers integrate with.

---

## 2. Subdomains

| Subdomain | Type | Purpose | Investment Level |
|-----------|------|---------|-----------------|
| **Authentication** | Core Domain | Verifying identity. The reason this service exists. | Highest. Best people, deepest modeling, most rigorous design. |
| **Audit** | Supporting Subdomain | Recording and exposing security-relevant events. Necessary for trust, compliance, and investigation. | Moderate. Needs custom modeling but is not the differentiator. |
| **Notification** | Generic Subdomain | Delivering messages (emails, SMS) to people. A solved problem. | Minimal. Integrate with external providers or expose hooks. Do not over-engineer. |

---

## 3. Bounded Contexts

Each subdomain is implemented as its own bounded context with explicit boundaries, its own model, and its own ubiquitous language.

### Authentication (Core Domain)

**Core Question:** Are you who you claim to be?

**What It Owns:**

| Concept | Description |
|---------|-------------|
| Identity | Its own aggregate. The unique, immutable reference to a person or system. Persists beyond Account. Shared across boundaries via its identifier. |
| Account | The stateful record associated with an Identity. Holds Credentials and MFA configuration. |
| Account Status | Lifecycle state of an Account: Unverified, Active, Locked, Suspended, Closed. |
| Credential | Evidence presented to prove an Identity claim. General concept with types. |
| Credential Type | Enum: Password, TOTP, Recovery Code. Extensible for future types. |
| Authentication Factor | Category of Credential: Knowledge, Possession, Inherence. |
| Password | A Knowledge Factor Credential. Stored hashed. Governed by Password Policy. |
| Password Policy | System-wide invariants governing password strength, history, expiration, and reuse. External to Account — injected into behaviors. |
| TOTP Secret | A Possession Factor Credential. Encrypted at rest. Decrypted only at validation time. |
| Recovery Code / Recovery Code Set | Knowledge Factor Credentials. Each code stored hashed. Generated as a batch. Raw codes shown once. |
| Verification Code | Temporary one-time code generated within Authentication Attempt for MFA via email/SMS. Stored hashed. Expires with the attempt. Not a Credential on the Account. |
| Multi-Factor Authentication | Requiring Credentials from two or more distinct factor categories. MFA Enabled flag on Account. |
| Authentication Attempt | Its own aggregate. A recorded instance of trying to verify an Identity. Tracks MFA progress internally. Generates Verification Codes on demand. |
| Failed Attempt Counter | Consecutive failure count on Account. Triggers Lockout. |
| Session | Its own aggregate. Time-bound period of authenticated access. Created only on full Authentication success. |
| Access Token | Stateless, signed payload. Not stored. Output of `Session.start()` and Refresh behavior. Contains only non-sensitive identifiers. |
| Refresh Token | Stateful. Stored hashed in DB. Revocation is instant. |
| Token Revocation | Invalidating a Refresh Token. Access Tokens expire naturally. |
| Login | Initiating Authentication with an Identity claim and Credentials. |
| Logout | Ending a Session and revoking its Refresh Token. |
| Account Lockout | Auto-locking an Account after excessive failed attempts. Revokes all Trusted Devices. Terminates all Sessions. |
| Throttling | Rate-limiting Authentication Attempts from a source. |
| Account Recovery | Separate process from Authentication for restoring access. |
| Recovery Request | Its own aggregate. A single Password Reset request with lifecycle: Pending → Verified → Completed / Expired. Owns the Recovery Token. |
| Password Reset | Replacing a forgotten Password via an alternative channel. Does not produce a Session. |
| Recovery Token | Single-use proof of channel ownership. Stored hashed within Recovery Request. Not an Authentication Credential. |
| Registration | Establishing a new Identity and Account. Account starts as Unverified. Triggers Email Verification Requested event. |
| Email Verification | Confirming email ownership. Transitions Account from Unverified to Active. |
| Trusted Device | Its own aggregate. A remembered device that may relax MFA requirements based on policy. |
| Device Fingerprint | Value object uniquely representing a device. |

**What It Does Not Own:**

- What the person is allowed to do (Authorization — consumer's responsibility)
- Personal details like name, avatar, preferences (User Profile — consumer's responsibility)
- How messages are physically delivered (Notification)
- Long-term event storage and compliance querying (Audit)

### Audit (Supporting Subdomain)

**Core Question:** What happened and when?

**What It Owns:**

| Concept | Description |
|---------|-------------|
| Audit Entry | A persistent, immutable record of a security-relevant event. Append-only. Event Payload contains identifiers and metadata only — no PII. |
| Event Timeline | The chronological sequence of events for a given Identity or Account. |
| Retention Policy | System-wide rules governing how long event records are kept before archival or deletion. |
| Audit Query | The ability to search, filter, and retrieve event records by Identity, Account, time range, event type, or combination. Subject to access control. |
| Compliance Report | Aggregated or filtered views of event records for regulatory or compliance purposes. |

Consumes all 30 Authentication domain events. See `auth-tactical-audit-notification.md` §2 for the canonical event list with payload details.

**What It Does Not Own:**

- The production of events (Authentication produces them)
- Short-term operational counters like failed attempt tracking for Lockout (that is Authentication's real-time state)
- Any decision-making about authentication or security policy
- PII — Audit stores identifiers, not personal data

### Notification (Generic Subdomain)

**Core Question:** How do we deliver messages to people?

**What It Owns:**

| Concept | Description |
|---------|-------------|
| Delivery Request | A request to send specific content to a specific destination via a specific channel. Sensitive requests have their content purged after delivery. |
| Delivery Channel | The medium through which a message is sent: Email, SMS. |
| Delivery Status | The outcome of a delivery attempt: Pending, Sent, Failed. |
| Retry Policy | System-wide rules governing how and when failed deliveries are retried. |
| Template | The structure and formatting of a message. Infrastructure concern, not a domain concept. |
| Delivery Request Cleanup Policy | Sensitive Delivery Requests (containing tokens or codes) must have content purged after delivery to prevent exposure. |

Consumes 3 delivery-trigger events from Authentication. See `auth-tactical-audit-notification.md` §3 Event-to-Delivery Mapping for details.

**What It Does Not Own:**

- The decision of what to send or why (Authentication decides)
- The content meaning (a Recovery Token's significance is Authentication's concern)
- Any authentication or security logic

---

## 4. Context Relationships

### Authentication → Audit (Conformist)

| Aspect | Detail |
|--------|--------|
| **Upstream** | Authentication |
| **Downstream** | Audit |
| **Communication** | Authentication publishes domain events. Audit subscribes. |
| **Coupling** | One-directional. Authentication does not know Audit exists. |
| **Model Ownership** | Audit adapts to Authentication's event model. If Authentication changes an event structure, Audit adjusts. Audit never asks Authentication to change its events. |
| **What Audit Does** | Subscribes to events, persists them as Audit Entries (no PII in payload — identifiers only), builds its own read models optimized for querying, filtering, and compliance reporting. |

### Authentication → Notification (Conformist)

| Aspect | Detail |
|--------|--------|
| **Upstream** | Authentication |
| **Downstream** | Notification |
| **Communication** | Authentication publishes domain events. Notification subscribes to the 3 events that require message delivery and translates them into Delivery Requests. |
| **Coupling** | One-directional. Authentication does not know Notification exists. |
| **Model Ownership** | Notification adapts to Authentication's event model. Notification translates Authentication's language into its own (events become Delivery Requests with content, destination, and channel). |
| **What Notification Does** | Receives events, determines the delivery channel, formats the message using templates, handles delivery, retries, and purges sensitive content after delivery. |

**Known Trade-Off:** Authentication does not receive feedback from Notification. If delivery permanently fails, Authentication has no awareness. This is intentional — introducing feedback would create a bidirectional dependency violating the Conformist relationship. Consumers can query Notification's Delivery Request status to investigate delivery failures.

### Service → Consumer Systems (Open Host Service + Published Language)

| Aspect | Detail |
|--------|--------|
| **Direction** | This service defines the contract. Consumers integrate with it. |
| **Published Language** | A deliberate, versioned subset of the ubiquitous language, translated for external consumption. |
| **Customization** | None. No per-consumer customization. All consumers use the same contract. |

**What the service exposes:**

| Capability | Description |
|-----------|-------------|
| Registration | Create an Identity and Account |
| Login | Authenticate and receive Tokens |
| Logout | End a Session |
| Token Refresh | Exchange a Refresh Token for a new Access Token |
| Token Validation | Verify that an Access Token is valid and retrieve the Identity ID |
| Password Reset | Initiate and complete Account Recovery |
| MFA Management | Enable, disable, and configure MFA for an Account |
| Trusted Device Management | List, register, and revoke Trusted Devices |
| Account Management | View and update Account Status |
| Audit Queries | Retrieve security event records. **Subject to access control** — consumers can only query records for Accounts and Identities created through their integration. |
| Delivery Status Queries | Check Notification delivery status for sent messages. |

**What the service never exposes:**

- Internal domain events or aggregate internals
- Notification delivery details beyond status
- Raw secrets, hashes, or encryption keys
- Any implementation specifics behind the contract

### Consumer Systems → Service (Conformist)

| Aspect | Detail |
|--------|--------|
| **Direction** | Consumers conform to the Published Language. |
| **The Bridge** | The Identity identifier. This is the only piece of data shared between this service and consumer systems. |

---

## 5. Token & Authorization Contract

| Decision | Detail |
|----------|--------|
| **Token content** | Identity only. The Access Token carries the Identity identifier, Account ID, Session ID, and timestamps. No sensitive data. |
| **Custom claims** | Not supported. Tokens carry no consumer-defined data. |
| **Authorization** | Entirely the consumer's responsibility. Not part of this service. |
| **Roles & Permissions** | Do not exist in this service. Consumers build their own Authorization system and map the Identity identifier to their own roles and permissions. |

**End-to-end flow:**

```
Person              This Service              Consumer's System
  │                      │                          │
  │── Login ────────────►│                          │
  │                      │                          │
  │◄── Access Token ─────│                          │
  │    (Identity ID only)│                          │
  │                      │                          │
  │── Request + Token ──────────────────────────────►│
  │                      │                          │
  │                      │◄── Validate Token ───────│
  │                      │── Valid, Identity ID ───►│
  │                      │                          │
  │                      │    Consumer looks up      │
  │                      │    roles/permissions in   │
  │                      │    their own system using │
  │                      │    the Identity ID        │
  │                      │                          │
  │◄──────────────────── Response (allowed or denied)│
```

---

## 6. Key Principles

| Principle | Description |
|-----------|-------------|
| Authentication is always upstream | It defines the model. Downstream contexts adapt. |
| Both downstream contexts are Conformist | Neither Audit nor Notification asks Authentication to change. They adapt to whatever Authentication publishes. |
| Authentication has no knowledge of downstream | It publishes events into the void. Who subscribes is not its concern. |
| The only shared data with consumers is the Identity identifier | No roles, no permissions, no profile data, no custom claims cross the boundary. |
| Consumers own their own Authorization | This service proves identity. What consumers do with that proof is their domain. |
| Audit records contain no PII | Identifiers and metadata only. Personal data is looked up in Authentication via Account ID when needed. |
| Audit queries are access-controlled | Consumers can only query records for their own Accounts and Identities. |
| Notification purges sensitive content | Delivery Requests containing tokens or codes have their content cleared after delivery. |

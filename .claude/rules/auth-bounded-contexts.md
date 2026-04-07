# Authentication Service — Bounded Contexts & Subdomains

---

## 1. Service Boundary

This is a **standalone authentication service** consumed by external systems. It answers one question: **"Are you who you claim to be?"**

The service does not own Authorization, User Profile, or any consumer-side concerns. It provides a contract that consumers integrate with.

---

## 2. Subdomains

### Problem Space Decomposition

The authentication problem space is divided into three subdomains, each with a different level of strategic importance:

| Subdomain | Type | Purpose | Investment Level |
|-----------|------|---------|-----------------|
| **Authentication** | Core Domain | Verifying identity. The reason this service exists. | Highest. Best people, deepest modeling, most rigorous design. |
| **Audit** | Supporting Subdomain | Recording and exposing security-relevant events. Necessary for trust, compliance, and investigation. | Moderate. Needs custom modeling but is not the differentiator. |
| **Notification** | Generic Subdomain | Delivering messages (emails, SMS) to people. A solved problem. | Minimal. Integrate with external providers or expose hooks. Do not over-engineer. |

### Why This Classification Matters

- **Authentication** is where competitive advantage lives. If this is wrong, the service fails. This is where DDD tactical patterns (Aggregates, Entities, Value Objects, Domain Events) are applied with full rigor.
- **Audit** supports the core but does not differentiate the product. It needs solid modeling but does not warrant the same depth as Authentication.
- **Notification** is not unique to this service. Every system sends emails and SMS. This is where you use existing solutions, not build from scratch.

---

## 3. Bounded Contexts

Each subdomain is implemented as its own bounded context with explicit boundaries, its own model, and its own ubiquitous language.

---

### Bounded Context 1: Authentication (Core Domain)

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

---

### Bounded Context 2: Audit (Supporting Subdomain)

**Core Question:** What happened and when?

**What It Owns:**

| Concept | Description |
|---------|-------------|
| Audit Entry | A persistent, immutable record of a security-relevant event. Append-only. Event Payload contains identifiers and metadata only — no PII. |
| Event Timeline | The chronological sequence of events for a given Identity or Account. |
| Retention Policy | System-wide rules governing how long event records are kept before archival or deletion. |
| Audit Query | The ability to search, filter, and retrieve event records by Identity, Account, time range, event type, or combination. Subject to access control. |
| Compliance Report | Aggregated or filtered views of event records for regulatory or compliance purposes. |

**What It Consumes:**

All 30 domain events published by Authentication:

| Category | Events |
|----------|--------|
| Identity | Identity Created |
| Authentication | Authentication Succeeded, Authentication Failed, Verification Code Generated |
| Account Lifecycle | Account Registered, Email Verification Requested, Email Verified, Account Locked, Account Unlocked, Account Suspended, Account Closed |
| Credentials | TOTP Secret Added, TOTP Secret Removed, Recovery Codes Generated, Recovery Code Consumed, Password Changed, MFA Enabled, MFA Disabled, Password Reset Completed |
| Session & Token | Session Started, Session Ended, Refresh Token Rotated |
| Account Recovery | Password Reset Requested, Recovery Token Issued, Recovery Token Verified, Recovery Request Completed, Password Reset Expired |
| Trusted Device | Device Trusted, Trusted Device Revoked, Trusted Device Expired |

**What It Does Not Own:**

- The production of events (Authentication produces them)
- Short-term operational counters like failed attempt tracking for Lockout (that is Authentication's real-time state)
- Any decision-making about authentication or security policy
- PII — Audit stores identifiers, not personal data

---

### Bounded Context 3: Notification (Generic Subdomain)

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

**What It Consumes:**

Three specific events from Authentication that require message delivery:

| Authentication Event | Notification Action | Channel |
|---------------------|-------------------|---------|
| **Email Verification Requested** | Deliver the verification link to the person | Email |
| **Verification Code Generated** | Deliver the one-time Verification Code to the person | Email or SMS (as specified in event payload) |
| **Recovery Token Issued** | Deliver the raw Recovery Token to the person | Email |

**What It Does Not Own:**

- The decision of what to send or why (Authentication decides)
- The content meaning (a Recovery Token's significance is Authentication's concern)
- Any authentication or security logic

---

## 4. Boundary Summary

```
┌──────────────────────────────────────────────────────────────────┐
│                    Authentication Service                         │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │           Authentication (Core Domain)                     │   │
│  │                                                            │   │
│  │  Identity (aggregate), Account (aggregate),                │   │
│  │  Session (aggregate), Trusted Device (aggregate),          │   │
│  │  Authentication Attempt (aggregate),                       │   │
│  │  Recovery Request (aggregate)                              │   │
│  │                                                            │   │
│  │  Credentials: Password, TOTP Secret, Recovery Codes        │   │
│  │  Verification Code (generated within Attempt)              │   │
│  │  Access Token (stateless output), Refresh Token (hashed)   │   │
│  │                                                            │   │
│  │  30 domain events published                                │   │
│  └────────────────┬──────────────────┬───────────────────────┘   │
│                   │                  │                            │
│          publishes events     publishes events                    │
│          (all 30)            (3 delivery triggers)                │
│                   │                  │                            │
│                   ▼                  ▼                            │
│  ┌───────────────────────┐  ┌─────────────────────────────┐     │
│  │  Audit (Supporting)   │  │  Notification (Generic)     │     │
│  │                       │  │                              │     │
│  │  Audit Entries         │  │  Delivery Request            │     │
│  │  (no PII),            │  │  (sensitive content purged), │     │
│  │  Queries (access-     │  │  Retry, Templates,           │     │
│  │  controlled),         │  │  Cleanup Policy              │     │
│  │  Retention Policy,    │  │                              │     │
│  │  Compliance Reports   │  │  Consumes 3 events:          │     │
│  │                       │  │  Email Verification Requested │     │
│  │  Consumes 30 events   │  │  Verification Code Generated  │     │
│  │                       │  │  Recovery Token Issued         │     │
│  └───────────────────────┘  └─────────────────────────────┘     │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Consumer Systems    │
              │                       │
              │  Authorization,       │
              │  User Profile,        │
              │  and anything else    │
              │  they own             │
              └───────────────────────┘
```

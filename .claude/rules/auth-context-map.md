# Authentication Service — Context Map

---

## 1. Overview

This document defines the relationships between the bounded contexts inside the Authentication Service, and between the service and external consumer systems.

The Authentication Service contains three bounded contexts:

| Context | Subdomain Type | Role |
|---------|---------------|------|
| **Authentication** | Core Domain | Upstream. Produces 30 domain events. Defines the model. |
| **Audit** | Supporting Subdomain | Downstream. Consumes all 30 Authentication events. Adapts to Authentication's model. |
| **Notification** | Generic Subdomain | Downstream. Consumes 3 specific Authentication events. Adapts to Authentication's model. |

---

## 2. Internal Relationships

### Authentication → Audit

| Aspect | Detail |
|--------|--------|
| **Relationship** | Conformist |
| **Upstream** | Authentication |
| **Downstream** | Audit |
| **Communication** | Authentication publishes domain events. Audit subscribes. |
| **Coupling** | One-directional. Authentication does not know Audit exists. |
| **Model Ownership** | Audit adapts to Authentication's event model. If Authentication changes an event structure, Audit adjusts. Audit never asks Authentication to change its events. |
| **What Audit Does** | Subscribes to events, persists them as Audit Entries (no PII in payload — identifiers only), builds its own read models optimized for querying, filtering, and compliance reporting. |

**All 30 events consumed by Audit:**

| Category | Events |
|----------|--------|
| Identity | Identity Created |
| Authentication | Authentication Succeeded, Authentication Failed, Verification Code Generated |
| Account Lifecycle | Account Registered, Email Verification Requested, Email Verified, Account Locked, Account Unlocked, Account Suspended, Account Closed |
| Credentials | TOTP Secret Added, TOTP Secret Removed, Recovery Codes Generated, Recovery Code Consumed, Password Changed, MFA Enabled, MFA Disabled, Password Reset Completed |
| Session & Token | Session Started, Session Ended, Refresh Token Rotated |
| Account Recovery | Password Reset Requested, Recovery Token Issued, Recovery Token Verified, Recovery Request Completed, Password Reset Expired |
| Trusted Device | Device Trusted, Trusted Device Revoked, Trusted Device Expired |

---

### Authentication → Notification

| Aspect | Detail |
|--------|--------|
| **Relationship** | Conformist |
| **Upstream** | Authentication |
| **Downstream** | Notification |
| **Communication** | Authentication publishes domain events. Notification subscribes to the 3 events that require message delivery and translates them into Delivery Requests. |
| **Coupling** | One-directional. Authentication does not know Notification exists. |
| **Model Ownership** | Notification adapts to Authentication's event model. Notification translates Authentication's language into its own (events become Delivery Requests with content, destination, and channel). |
| **What Notification Does** | Receives events, determines the delivery channel, formats the message using templates, handles delivery, retries, and purges sensitive content after delivery. |

**3 events consumed by Notification:**

| Authentication Event | Notification Action | Channel |
|---------------------|-------------------|---------|
| **Email Verification Requested** | Deliver the verification link to the person | Email |
| **Verification Code Generated** | Deliver the one-time Verification Code to the person | Email or SMS (as specified in event payload) |
| **Recovery Token Issued** | Deliver the raw Recovery Token to the person | Email |

**Known Trade-Off:** Authentication does not receive feedback from Notification. If delivery permanently fails, Authentication has no awareness. This is intentional — introducing feedback would create a bidirectional dependency violating the Conformist relationship. Consumers can query Notification's Delivery Request status to investigate delivery failures.

---

## 3. External Relationships

### Your Service → Consumer Systems

| Aspect | Detail |
|--------|--------|
| **Relationship** | Open Host Service + Published Language |
| **Direction** | Your service defines the contract. Consumers integrate with it. |
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
| Audit Queries | Retrieve security event records. **Subject to access control** — consumers can only query records for Accounts and Identities created through their integration. Endpoints are protected with strong authentication and rate limiting. |
| Delivery Status Queries | Check Notification delivery status for sent messages (operational investigation of delivery failures). |

**What the service never exposes:**

- Internal domain events or aggregate internals
- Notification delivery details beyond status
- Raw secrets, hashes, or encryption keys
- Any implementation specifics behind the contract

### Consumer Systems → Your Service

| Aspect | Detail |
|--------|--------|
| **Relationship** | Conformist |
| **Direction** | Consumers conform to your Published Language. |
| **The Bridge** | The Identity identifier. This is the only piece of data shared between your service and consumer systems. |

---

## 4. Token & Authorization Contract

| Decision | Detail |
|----------|--------|
| **Token content** | Identity only. The Access Token proves "this Identity was authenticated at this time" and carries the Identity identifier, Account ID, Session ID, and timestamps. No sensitive data. |
| **Custom claims** | Not supported. Tokens carry no consumer-defined data. |
| **Authorization** | Entirely the consumer's responsibility. Not part of this service. |
| **Roles & Permissions** | Do not exist in this service. Consumers build their own Authorization system and map your Identity identifier to their own roles and permissions. |

**End-to-end flow:**

```
Person              Your Service              Consumer's System
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

## 5. Context Map Diagram

```
                    Consumer Systems
                    (Conformist to Published Language)
                          │
                          ▼
              ┌───────────────────────┐
              │    Open Host Service  │
              │  + Published Language │
              │                       │
              │  Token carries        │
              │  Identity ID only.    │
              │  No custom claims.    │
              │  No roles/permissions.│
              │                       │
              │  Audit queries are    │
              │  access-controlled.   │
              └───────────┬───────────┘
                          │
    ┌─────────────────────┼─────────────────────────┐
    │            Authentication Service              │
    │                                                │
    │   ┌────────────────────────────────────────┐   │
    │   │    Authentication (Core Domain)         │   │
    │   │              UPSTREAM                   │   │
    │   │                                         │   │
    │   │  Publishes 30 domain events.            │   │
    │   │  Does not know downstream exists.       │   │
    │   └──────────┬──────────────┬──────────────┘   │
    │              │              │                   │
    │         Conformist      Conformist              │
    │         (30 events)     (3 events)              │
    │              │              │                   │
    │              ▼              ▼                   │
    │   ┌──────────────┐  ┌─────────────────────┐   │
    │   │    Audit     │  │    Notification      │   │
    │   │  (Supporting)│  │    (Generic)         │   │
    │   │  DOWNSTREAM  │  │    DOWNSTREAM        │   │
    │   │              │  │                       │   │
    │   │  Subscribes  │  │  Subscribes to:       │   │
    │   │  to all 30   │  │  - Email Verification │   │
    │   │  events.     │  │    Requested          │   │
    │   │  Persists    │  │  - Verification Code  │   │
    │   │  records     │  │    Generated          │   │
    │   │  (no PII).   │  │  - Recovery Token     │   │
    │   │              │  │    Issued              │   │
    │   │  Queries are │  │                       │   │
    │   │  access-     │  │  Delivers messages.   │   │
    │   │  controlled. │  │  Purges sensitive      │   │
    │   │              │  │  content after         │   │
    │   │              │  │  delivery.             │   │
    │   └──────────────┘  └─────────────────────┘   │
    │                                                │
    └────────────────────────────────────────────────┘
```

---

## 6. Key Principles

| Principle | Description |
|-----------|-------------|
| Authentication is always upstream | It defines the model. Downstream contexts adapt. |
| Both downstream contexts are Conformist | Neither Audit nor Notification asks Authentication to change. They adapt to whatever Authentication publishes. |
| Authentication has no knowledge of downstream | It publishes events into the void. Who subscribes is not its concern. If Notification fails to deliver, Authentication doesn't know — and that's intentional. |
| The only shared data with consumers is the Identity identifier | No roles, no permissions, no profile data, no custom claims cross the boundary. |
| Consumers own their own Authorization | Your service proves identity. What consumers do with that proof is their domain. |
| Audit records contain no PII | Identifiers and metadata only. Personal data is looked up in Authentication via Account ID when needed. |
| Audit queries are access-controlled | Consumers can only query records for their own Accounts and Identities. |
| Notification purges sensitive content | Delivery Requests containing tokens or codes have their content cleared after delivery. |

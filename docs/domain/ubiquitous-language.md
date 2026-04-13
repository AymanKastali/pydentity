# Ubiquitous Language

The Ubiquitous Language is the shared vocabulary between developers and domain experts, used consistently in code, documentation, and conversation (Evans, DDD Ch. 2). Every class, method, and variable in the domain layer must use these exact terms. If the code uses different words than this glossary, the model is wrong.

This glossary is the single source of truth for naming in the pydentity identity management system. It is organized by bounded context — the same term may carry different meaning across contexts, which is a sign of correctly separated boundaries.

---

## Shared Kernel

| Term | Type | Definition |
|------|------|------------|
| Account ID | Value Object | Unique identifier (UUID) for an account, shared across all bounded contexts. |
| Device ID | Value Object | Unique identifier (UUID) for a registered device. |
| Event Name | Value Object | The name of a domain event, used to classify audit entries. |

## Authentication

### Account

| Term | Type | Definition |
|------|------|------------|
| Account | Aggregate Root | Represents a user's identity. Holds credentials, tracks status, and enforces authentication and security rules. |
| Email Password Credential | Entity | The email and hashed password pair used to authenticate an account. Maintains password history. |
| Credential ID | Value Object | Unique identifier (UUID) for a credential entity. |
| Email | Value Object | An email address associated with an account. |
| Raw Password | Value Object | A plaintext password before hashing. Never persisted. |
| Hashed Password | Value Object | A password after cryptographic hashing. The only form stored. |
| Failed Attempt Count | Value Object | The number of consecutive failed login attempts for an account. |
| Password Policy | Value Object | Rules governing password requirements: minimum length, maximum length, and history depth. |
| Lockout Policy | Value Object | Rules governing account lockout: maximum failed attempts before lockout and lockout duration. |
| Account Status | Enum | The lifecycle state of an account: Pending Verification, Active, Locked, Suspended, or Closed. |
| Lock Reason | Enum | Why an account was locked: failed attempt threshold exceeded or administrative action. |
| Unlock Reason | Enum | Why an account was unlocked: lockout duration expiry or administrative action. |
| Password Hasher | Domain Interface | Hashes a raw password into a hashed password. |
| Password Verifier | Domain Interface | Verifies a raw password against a hashed password. |
| Compromised Password Checker | Domain Interface | Checks whether a password appears in known breach databases. |
| Email Verifier | Domain Interface | Validates whether an email address is syntactically valid. |
| Prevent Duplicate Email | Domain Service | Ensures no two accounts share the same email address. |
| Authenticate Account | Domain Service | Verifies a raw password against a hashed password. Raises an error on mismatch. No aggregate mutation — caller handles recording success or failure on the Account. |
| Change Account Password | Domain Service | Validates the current password, checks the new password against policy, breach database, and password history. Returns a Hashed Password for the caller to apply. |
| Change Account Email | Domain Service | Validates email format and ensures uniqueness. Caller applies the change on the Account. |
| Register Account | Domain Service | Orchestrates account creation: validates email, checks password policy and breach database, ensures email uniqueness, hashes the password, and delegates to Account.create(). |
| Account Registered | Domain Event | An account has been created. |
| Login Succeeded | Domain Event | An authentication attempt succeeded. |
| Login Failed | Domain Event | An authentication attempt failed. Carries the current failed attempt count. |
| Email Verified | Domain Event | An account's email address has been confirmed. |
| Email Changed | Domain Event | An account's email address has been updated. |
| Password Changed | Domain Event | An account's password has been updated. |
| Account Locked | Domain Event | An account has been locked, with a reason. |
| Account Unlocked | Domain Event | An account has been unlocked, with a reason. |
| Account Suspended | Domain Event | An account has been suspended by an administrator. |
| Account Closed | Domain Event | An account has been permanently closed. |

### Session

| Term | Type | Definition |
|------|------|------------|
| Session | Aggregate Root | Represents an active authenticated period for an account on a specific device. |
| Session ID | Value Object | Unique identifier (UUID) for a session. |
| Session Policy | Value Object | Rules governing session duration: time-to-live in seconds. |
| Session Expiry | Value Object | The point in time after which a session is no longer valid. |
| Session Status | Enum | Whether a session is Active or Ended. |
| Session End Reason | Enum | Why a session ended: Logout, Expired, Forced termination, or Compromise detection. |
| Terminate Sessions | Domain Service | Ends all active sessions for a given device, with a specified reason. |
| Session Started | Domain Event | A new session has begun. |
| Session Ended | Domain Event | A session has ended, with a reason. |
| Session Refreshed | Domain Event | A session's expiration has been extended. |

### Device

| Term | Type | Definition |
|------|------|------------|
| Device | Aggregate Root | Represents a registered device associated with an account, identified by a hashed fingerprint. |
| Raw Device Fingerprint | Value Object | A plaintext device fingerprint before hashing. Never persisted. |
| Hashed Device Fingerprint | Value Object | A device fingerprint after cryptographic hashing. The only form stored. |
| Device Policy | Value Object | Rules governing device management: maximum number of active devices per account. |
| Device Status | Enum | Whether a device is Active or Revoked. |
| Device Revocation Reason | Enum | Why a device was revoked: Manual by user, Admin action, Lockout, or Account Closure. |
| Device Fingerprint Hasher | Domain Interface | Hashes a raw device fingerprint. |
| Device Fingerprint Verifier | Domain Interface | Verifies a raw device fingerprint against a hashed one. |
| Register Device | Domain Service | Registers a new device for an account, enforcing the maximum device limit. |
| Revoke Devices | Domain Service | Revokes all devices for an account, with a specified reason. |
| Device Registered | Domain Event | A new device has been registered for an account. |
| Device Revoked | Domain Event | A device has been revoked, with a reason. |

### Verification

| Term | Type | Definition |
|------|------|------------|
| Verification Request | Aggregate Root | Represents a time-limited request to verify an action (email verification or password reset). Identified by a hashed token. |
| Verification Request ID | Value Object | Unique identifier (UUID) for a verification request. |
| Raw Verification Request Token | Value Object | A plaintext verification token before hashing. Sent to the user, never persisted. |
| Hashed Verification Request Token | Value Object | A verification token after cryptographic hashing. The only form stored. |
| Verification Policy | Value Object | Rules governing verification request lifetimes: TTL for email verification and password reset requests. |
| Verification Request Expiry | Value Object | The point in time after which a verification request is no longer valid. |
| Verification Request Status | Enum | The lifecycle state of a verification request: Pending, Verified, Invalidated, or Expired. |
| Verification Request Type | Enum | The kind of verification: Email Verification or Password Reset. |
| Verification Failure Reason | Enum | Why a verification attempt failed: Invalid Token, Expired, or Already Verified. |
| Verification Request Token Hasher | Domain Interface | Hashes a raw verification token. |
| Verification Request Token Verifier | Domain Interface | Verifies a raw verification token against a hashed one. |
| Issue Email Verification Request | Domain Service | Invalidates pending email verification requests for the account, hashes the token, computes expiry, and creates a new verification request. |
| Issue Password Reset Request | Domain Service | Invalidates pending password reset requests for the account, hashes the token, computes expiry, and creates a new verification request. |
| Verify Verification Request Token | Domain Service | Checks expiry, verifies the token against the hash, and transitions the request to Verified on success. |
| Verification Request Created | Domain Event | A new verification request has been created. |
| Verification Request Verified | Domain Event | A verification request has been successfully verified. |
| Verification Request Failed | Domain Event | A verification attempt failed, with a reason. |
| Verification Request Invalidated | Domain Event | A verification request has been invalidated. |
| Verification Request Expired | Domain Event | A verification request has expired. |

---

## Audit

| Term | Type | Definition |
|------|------|------------|
| Audit Entry | Aggregate Root | An immutable record of a domain event that occurred in the system. Captures what happened and to whom. |
| Audit Entry ID | Value Object | Unique identifier (UUID) for an audit entry. |
| Event Payload | Value Object | A collection of key-value pairs providing additional context about the audited event. |

---

## Notification

| Term | Type | Definition |
|------|------|------------|
| Delivery Request | Aggregate Root | Represents a request to deliver a message to a user through a specific channel. Tracks delivery status and retry attempts. |
| Delivery Request ID | Value Object | Unique identifier (UUID) for a delivery request. |
| Recipient | Value Object | The address to which a message should be delivered. |
| Message Content | Value Object | The subject and body of a message. Purged after delivery for sensitive content. |
| Attempt Count | Value Object | The number of delivery attempts made for a request. |
| Channel | Enum | The delivery method: Email or SMS. |
| Content Sensitivity | Enum | Whether message content is Sensitive (must be purged after delivery) or Standard. |
| Delivery Status | Enum | The state of a delivery request: Pending, Sent, or Failed. |
| Message Delivered | Domain Event | A message has been successfully delivered. |
| Message Delivery Failed | Domain Event | A message delivery has permanently failed. |

---

## Domain Sentences

These sentences exercise the Ubiquitous Language across bounded contexts. If a sentence sounds awkward when spoken aloud, the model needs revision (Evans, DDD Ch. 2 — Modeling Out Loud).

### Authentication

- An **Account** is created through the **Register Account** service, which validates the **Email** via the **Email Verifier**, checks the **Raw Password** against the **Compromised Password Checker** and the **Password Policy**, ensures email uniqueness via **Prevent Duplicate Email**, hashes the password using the **Password Hasher**, and delegates to `Account.create()`. The Account starts in **Pending Verification** status.
- When a user authenticates, the **Authenticate Account** service verifies the **Raw Password** against the **Hashed Password** using the **Password Verifier**. The caller then records the outcome on the Account: on success, `record_login_success` resets the **Failed Attempt Count**; on failure, `record_login_failure` increments it. If the count exceeds the **Lockout Policy** threshold, the Account is locked, and an **Account Locked** event is recorded.
- A **Verification Request** is created by **Issue Email Verification Request** or **Issue Password Reset Request**, which invalidates any pending request of the same type, hashes the **Raw Verification Request Token** with the **Verification Request Token Hasher**, computes the **Verification Request Expiry** from the **Verification Policy**, and delegates to `VerificationRequest.create()`. The raw token is returned to the caller for delivery.
- **Verify Verification Request Token** checks the request's expiry and verifies the token against the **Hashed Verification Request Token** using the **Verification Request Token Verifier**. On success, the request transitions from **Pending** to **Verified**.
- A **Session** is created via `Session.create()`, which sets the **Session Expiry** and binds the Session to an **Account** and a **Device** by their IDs.
- **Register Device** registers a new **Device** for an Account, hashing the **Raw Device Fingerprint** with the **Device Fingerprint Hasher** and enforcing the **Device Policy** limit. If the limit is exceeded, registration is rejected.
- When an Account is locked, **Revoke Devices** revokes all active Devices and **Terminate Sessions** ends all active Sessions for each revoked Device.

### Audit

- When a domain event occurs in the Authentication context, the Audit context records an **Audit Entry** using the `record` factory method. The entry captures the **Event Name**, the **Account ID**, and an **Event Payload** containing key-value context about the event.

### Notification

- When an **Account Registered** event occurs, the Notification context creates a **Delivery Request** with Channel **Email**, a **Recipient** address, **Message Content** containing the welcome message, and **Standard** sensitivity.
- When a **Verification Request Created** event occurs for a password reset, a **Delivery Request** is created with **Sensitive** content sensitivity. After the message is marked as **Sent**, the **Message Content** is purged.

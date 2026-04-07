# Ubiquitous Language — Authentication Service

This document defines the shared vocabulary for the Authentication Service. Every term here means exactly one thing. Use these terms in conversation, code, documentation, and design discussions.

---

## What This Service Does

The Authentication Service answers one question: **"Are you who you claim to be?"**

It does **not** answer "What are you allowed to do?" — that is Authorization, which belongs to consumer systems.

---

## Core Concepts

| Term | Definition |
|------|------------|
| **Identity** | The unique, permanent representation of a person or system. Never changes. Survives even if the Account is closed. Other systems reference a person by their Identity identifier. |
| **Account** | The record associated with an Identity. Holds credentials, MFA settings, and lifecycle status. If Identity is "who you are," Account is "the file we keep on you." One Identity has exactly one Account. |
| **Account Status** | The current state of an Account. Determines what operations are allowed. See [Account Lifecycle](#account-lifecycle) below. |
| **MFA Enabled** | A flag on the Account indicating whether Multi-Factor Authentication is required at login. Can only be turned on when the Account has at least one non-password credential. |

---

## Credentials and Factors

| Term | Definition |
|------|------------|
| **Credential** | Any piece of evidence presented to prove an identity claim. Passwords, TOTP secrets, and recovery codes are all types of credentials. |
| **Credential Type** | The kind of credential: Password, TOTP, or Recovery Code. |
| **Authentication Factor** | A category of credential. **Knowledge** (something you know), **Possession** (something you have), **Inherence** (something you are). |
| **Password** | A Knowledge Factor credential. Subject to the Password Policy. |
| **Password Policy** | System-wide rules governing password strength, history, and reuse. Not tied to individual accounts — the same rules apply to everyone. |
| **TOTP Secret** | A Possession Factor credential. The shared secret used with an authenticator app to generate time-based one-time passwords. |
| **Recovery Code** | A Knowledge Factor credential. A single-use backup code. Shown to the person once at generation time, then only hashes are retained. |
| **Recovery Code Set** | A batch of recovery codes generated together. The entire set is replaced when regenerated. |
| **Password History** | Previous passwords kept on file to enforce reuse restrictions defined in Password Policy. |
| **Verification Code** | A temporary, short-lived one-time code generated during MFA when a second factor is needed via email or SMS. Lives only within the current login attempt — it is not a credential stored on the Account. |
| **Multi-Factor Authentication (MFA)** | Requiring credentials from **two or more distinct factor categories** to complete a login. A password plus a TOTP code qualifies. Two passwords do not. |

---

## Sessions and Tokens

| Term | Definition |
|------|------------|
| **Session** | A time-bound period of authenticated access. Begins when login fully succeeds (all required factors verified). Ends through logout, expiration, or forced termination. |
| **Token** | A digital artifact representing a successful login. The mechanism through which a Session is maintained. |
| **Access Token** | A short-lived token (minutes). Self-contained — carries only non-sensitive identifiers (Identity ID, Account ID, Session ID) and timestamps. Not stored by the service. Cannot be revoked — it expires naturally. |
| **Refresh Token** | A longer-lived token (days to weeks). Stored by the service. Used solely to obtain a new Access Token without re-authenticating. Can be revoked instantly. |
| **Token Revocation** | Invalidating a Refresh Token before it naturally expires. Access Tokens cannot be revoked. |

---

## Authentication Process

| Term | Definition |
|------|------------|
| **Authentication** | The process of verifying a claimed identity by validating one or more credentials. Either fully succeeds or fails — no partial success. |
| **Login** | Initiating authentication by presenting an identity claim (email) and credentials. |
| **Logout** | Explicitly ending a Session and revoking its Refresh Token. |
| **Authentication Attempt** | A single recorded instance of trying to verify an identity. Tracks which factors have been verified so far (internally — no one outside can see partial progress). If abandoned, it expires silently. |
| **Failed Attempt Counter** | A count of consecutive failed login attempts on an Account. Resets to zero on success. Triggers lockout when a threshold is reached. |
| **Account Lockout** | Automatically locking an Account after too many consecutive failed attempts. All trusted devices are revoked and all sessions are terminated. |
| **Throttling** | Rate-limiting login attempts from a source to prevent brute-force attacks. Operates on the source, while lockout operates on the Account. |

---

## Account Recovery

| Term | Definition |
|------|------------|
| **Account Recovery** | A process **separate from authentication** for restoring access when normal login is not possible. Password reset is one form. |
| **Recovery Request** | A single password reset request with a defined lifecycle: Pending, Verified, Completed, or Expired. Only one active request per Account at a time. |
| **Password Reset** | Replacing a forgotten password through an alternative channel (email). The person is proving channel ownership, not authenticating. Does **not** produce a Session — the person must log in normally afterward. |
| **Recovery Token** | A temporary, single-use proof of channel ownership used during password reset. Not a login credential. Exists only within the recovery process. |

---

## Registration and Verification

| Term | Definition |
|------|------------|
| **Registration** | Creating a new Identity and its associated Account. The Account starts in Unverified status. A verification email is sent automatically. |
| **Email Verification** | Confirming that a person owns the email address they registered with. Transitions the Account from Unverified to Active. |

---

## Trusted Devices

| Term | Definition |
|------|------------|
| **Trusted Device** | A device that has been explicitly remembered for a specific Account. May allow relaxation of MFA requirements based on policy — not automatically. |
| **Device Fingerprint** | A value that uniquely represents a device. How it is generated is an implementation detail. |

---

## Account Lifecycle

```
Registration
    |
    v
 Unverified ----> Active
                   |    ^    |
          Lockout  |    |    |  Admin
          (auto)   v    |    |  Action
                 Locked-+    |
                  Unlock     v
                         Suspended
                              |
                              v
                           Closed
```

| Status | Meaning | Can Log In? |
|--------|---------|-------------|
| **Unverified** | Account created, email not yet verified | No |
| **Active** | Fully operational | Yes |
| **Locked** | Auto-locked due to too many failed attempts | No |
| **Suspended** | Administratively disabled | No |
| **Closed** | Permanently deactivated. Identity still exists. | No |

---

## Trusted Device Lifecycle

| Status | Meaning |
|--------|---------|
| **Registered** | Device is trusted and may influence MFA policy |
| **Revoked** | Trust removed (manually, by admin, or due to lockout/closure) |
| **Expired** | Trust period elapsed naturally |

---

## Recovery Request Lifecycle

| Status | Meaning |
|--------|---------|
| **Pending** | Token issued and sent. Awaiting the person to present it. |
| **Verified** | Token validated. Password reset is now permitted. |
| **Completed** | Password successfully reset. Request is closed. |
| **Expired** | Token expired before it was used. |

---

## Domain Events

Events are facts about things that happened. They are published by the Authentication context and consumed by Audit (all events) and Notification (3 specific events).

### Identity Events
- **Identity Created** — a new Identity was established

### Authentication Events
- **Authentication Succeeded** — all required factors verified
- **Authentication Failed** — an invalid credential was presented
- **Verification Code Generated** — a one-time code was created for email/SMS MFA

### Account Lifecycle Events
- **Account Registered** — a new Account was created
- **Email Verification Requested** — a verification email needs to be sent
- **Email Verified** — email ownership confirmed, Account is now Active
- **Account Locked** — too many failed attempts, Account auto-locked
- **Account Unlocked** — Account restored from Locked to Active
- **Account Suspended** — Account administratively disabled
- **Account Closed** — Account permanently deactivated

### Credential Events
- **TOTP Secret Added** / **TOTP Secret Removed**
- **Recovery Codes Generated** — new batch of backup codes created
- **Recovery Code Consumed** — a single-use backup code was used
- **Password Changed** — password replaced via the change password flow
- **Password Reset Completed** — password replaced via account recovery
- **MFA Enabled** / **MFA Disabled**

### Session and Token Events
- **Session Started** — new session began after successful login
- **Session Ended** — session terminated (logout, timeout, or forced)
- **Refresh Token Rotated** — refresh token replaced with a new one

### Account Recovery Events
- **Password Reset Requested** — person initiated a password reset
- **Recovery Token Issued** — recovery token generated and sent
- **Recovery Token Verified** — person presented a valid recovery token
- **Recovery Request Completed** — recovery request closed after password reset
- **Password Reset Expired** — recovery token expired before use

### Trusted Device Events
- **Device Trusted** — a device was registered as trusted
- **Trusted Device Revoked** — trust removed from a device
- **Trusted Device Expired** — trust period elapsed

---

## Key Rules

- **Authentication is all-or-nothing.** No partial success. All required factors must pass before a session or token is created.
- **One Identity, one Account.** A person logs in one way. Consumer systems handle roles and tenants.
- **Identity survives Account closure.** Other systems may still reference it.
- **Account Recovery does not produce a Session.** After a password reset, the person must log in normally.
- **Lockout revokes all trusted devices and terminates all sessions.**
- **Password change terminates all sessions.** The person must re-authenticate.
- **Access Tokens cannot be revoked.** They expire naturally. Only Refresh Tokens can be revoked.
- **This service does not handle authorization.** It proves identity. What consumers do with that proof is their domain.

---

## What This Service Exposes to Consumers

The only piece of data shared between this service and consumer systems is the **Identity identifier**. The Access Token carries the Identity ID, Account ID, Session ID, and timestamps — nothing else. No roles, no permissions, no profile data, no custom claims.

Consumers own their own authorization. This service proves who someone is. What they are allowed to do is not our concern.

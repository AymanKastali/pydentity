# Authentication Domain — Ubiquitous Language

---

## 1. Context Boundary

The Authentication bounded context answers one question: **"Are you who you claim to be?"**

It does **not** answer "What are you allowed to do?" — that is Authorization, a separate bounded context.

---

## 2. Foundational Modeling Decisions

| # | Decision | Implication |
|---|----------|-------------|
| 1 | Identity and Account are two separate concepts | Identity is the immutable "who," modeled as its own aggregate. Account is the stateful record, modeled as a separate aggregate. Account knows its Identity; Identity does not know about the Account. |
| 2 | Authentication is all-or-nothing | No "partially authenticated" state. MFA progress is internal to the Authentication Attempt. No Session or Token is issued until all factors pass. |
| 3 | Password Reset is Account Recovery, not Authentication | Separate process modeled as the Recovery Request aggregate. Separate events, separate lifecycle. Does not produce a Session. Person must authenticate normally after recovery. |
| 4 | Trusted Device is a first-class domain concept | Has a lifecycle (Registered → Revoked / Expired). Belongs to an Account. Influences Authentication policy from the start. |
| 5 | One Identity, one Account | An Identity has exactly one Account. A single person logs in one way; downstream contexts handle any role or tenant separation. |
| 6 | Hybrid token storage | Access Token is stateless (signed payload, not stored). Refresh Token is stateful (stored hashed). Revocation targets the Refresh Token; Access Token expires naturally. |
| 7 | Password Policy is external to Account | System-wide rule. Not owned by individual Accounts. Injected into behaviors that evaluate password validity. |
| 8 | Credential is a general concept with types | Extensible model. Supported types: Password, TOTP, Recovery Code. New types can be added without restructuring. |
| 9 | Verification Code is generated within the Authentication Attempt | During MFA via email/SMS, a temporary hashed code is generated on demand within the attempt, delivered via Notification, and validated when presented. |

---

## 3. Glossary

### Core Concepts

| Term | Definition |
|------|------------|
| **Identity** | The unique, immutable representation of a person or system. Its own aggregate. Carries no state, no credentials, no lifecycle beyond existence. Its identifier never changes. Persists even if the Account is closed. May be referenced by other bounded contexts. |
| **Account** | The persistent, stateful record associated with an Identity. Holds Credentials, the current Account Status, Failed Attempt Counter, and MFA configuration. If Identity is "who," Account is "the file we keep on who." One Identity has exactly one Account. |
| **Account Status** | The current state of an Account. Governs what operations are permitted. See §4 for the full list of statuses and transitions. |
| **MFA Enabled** | A boolean attribute on the Account indicating whether Multi-Factor Authentication is required. Can only be enabled when at least one non-Password credential exists (TOTP or Recovery Codes). |

### Credentials & Factors

| Term | Definition |
|------|------------|
| **Credential** | Any piece of evidence that can be presented to prove an Identity claim. The general concept — Passwords, TOTP Secrets, Recovery Codes, and Verification Codes are all types or derivatives. Each Credential has a Credential Type. |
| **Credential Type** | Enum: Password, TOTP, Recovery Code. Classifies the Credential and ties it to an Authentication Factor category. |
| **Authentication Factor** | A category of Credential. Three types: Knowledge Factor (something you know), Possession Factor (something you have), Inherence Factor (something you are). |
| **Password** | A Knowledge Factor Credential. Stored as a **one-way hash** (never plain text). Subject to the Password Policy. |
| **Password Policy** | The set of invariants governing password strength, history, and lifecycle: minimum length, complexity, expiration, and reuse restrictions. **System-wide rule, external to Account.** Injected into behaviors that evaluate password validity. |
| **TOTP Secret** | A Possession Factor Credential. A shared secret used with an authenticator app to generate time-based one-time passwords. **Encrypted at rest** (not hashed) because the service must read the raw secret to validate TOTP codes. Decrypted only at validation time. |
| **Recovery Code** | A Knowledge Factor Credential. A single-use backup code. Stored as a **one-way hash.** When presented, the input is hashed and compared. Once used, marked and cannot be reused. |
| **Recovery Code Set** | A batch of Recovery Codes generated together. Raw codes shown to the person exactly once at generation time, then only hashes retained. Entire set replaced when regenerated. |
| **Hashed Password History** | Ordered list of previous password hashes. Used to enforce reuse restrictions defined in Password Policy. |
| **Verification Code** | A temporary, short-lived one-time code generated on demand during MFA when a Possession Factor via email/SMS is required. Stored **hashed** within the Authentication Attempt. Raw value emitted via event for delivery by Notification. Expires with the attempt. **Not a Credential on the Account** — it exists entirely within the Authentication Attempt lifecycle. |
| **Multi-Factor Authentication (MFA)** | Requiring Credentials from **two or more distinct Authentication Factor categories** to complete Authentication. A password plus a TOTP code qualifies. A password plus a Verification Code qualifies. Two passwords do not. |

### Sessions & Tokens

| Term | Definition |
|------|------------|
| **Session** | A time-bound period of authenticated access. Begins when Authentication fully succeeds (all required factors verified). Ends through Logout, expiration, or revocation. |
| **Token** | A digital artifact representing a successful Authentication. The mechanism through which a Session is maintained. |
| **Access Token** | A short-lived Token (5–15 minutes). Stateless — a self-contained signed payload containing only non-sensitive identifiers (Identity ID, Account ID, Session ID) and timestamps. **Not stored in DB. Not part of any aggregate's state.** Generated as output of `Session.start()` and the Session Refresh behavior. Validated by verifying the signature and checking expiration. |
| **Refresh Token** | A longer-lived Token (days to weeks). Stateful — **stored in DB as a one-way hash** (never raw). Used solely to obtain a new Access Token without re-authentication. Revocation is instant by marking as revoked or deleting from DB. |
| **Token Revocation** | The act of invalidating a Refresh Token before its natural expiration. Access Tokens cannot be revoked — they expire naturally. |

### Authentication Process

| Term | Definition |
|------|------------|
| **Authentication** | The process of verifying a claimed Identity by validating one or more Credentials. Either succeeds or fails — no partial success. |
| **Login** | The act of initiating Authentication by presenting an Identity claim and one or more Credentials. |
| **Logout** | The explicit act of ending a Session and revoking its Refresh Token. |
| **Authentication Attempt** | A single, recorded instance of trying to verify an Identity. Its own aggregate. Results in Success, Failure, or Expiration. During MFA, internally tracks which factors have been verified (invisible to the rest of the domain). Generates Verification Codes on demand for email/SMS MFA. If abandoned, the attempt expires. |
| **Failed Attempt Counter** | A count of consecutive failed Authentication Attempts on an Account. Resets to zero on success. Triggers Account Lockout when threshold is reached. |
| **Account Lockout** | Automatically transitioning an Account to Locked status after a threshold of consecutive failed Authentication Attempts. All Trusted Devices are revoked and all Sessions are terminated upon lockout. |
| **Throttling** | Rate-limiting Authentication Attempts from a source to prevent brute-force attacks. Operates on the source, while Lockout operates on the Account. |

### Account Recovery

| Term | Definition |
|------|------------|
| **Account Recovery** | A process **separate from Authentication**. Restores access when normal Authentication is not possible. Password Reset is one form. |
| **Recovery Request** | Its own aggregate. Represents a single Password Reset request with a defined lifecycle: Pending → Verified → Completed or Expired. Only one active Recovery Request per Account at a time. Creating a new one invalidates any previous pending request. |
| **Recovery Request Status** | Enum: Pending (token issued, awaiting verification), Verified (token validated, password reset permitted), Completed (password successfully reset), Expired (token expired before use). |
| **Password Reset** | The process of replacing a forgotten Password through an alternative channel. The person is not authenticating — they are proving channel ownership via a Recovery Token to earn the right to replace a Credential. Does not produce a Session. Person must authenticate normally afterward. |
| **Recovery Token** | A temporary, single-use proof of channel ownership. Stored as a **one-way hash** (never raw) within the Recovery Request aggregate. Not an Authentication Credential. Exists only within the Account Recovery process. |

### Registration

| Term | Definition |
|------|------------|
| **Registration** | The process of establishing a new Identity (its own aggregate) and its associated Account. Ends with an Account in Unverified status. Triggers Email Verification Requested event for Notification to deliver a verification link. |
| **Email Verification** | The process of confirming that an Identity owns a claimed email address. Transitions an Account from Unverified to Active. |

### Trusted Device

| Term | Definition |
|------|------------|
| **Trusted Device** | Its own aggregate. A device previously verified and explicitly remembered for a specific Account. May allow relaxation of certain Authentication steps (e.g., MFA) based on policy — not automatically. |
| **Device Fingerprint** | A value object that uniquely represents a device. The concept exists in the domain language; how the fingerprint is generated is an implementation detail. |

---

## 4. Account Status Lifecycle

```
Registration
    │
    ▼
┌────────────┐   Email Verification   ┌────────────┐
│ Unverified │ ──────────────────────► │   Active   │
└────────────┘                         └────────────┘
                                        │    ▲    │
                          Lockout       │    │    │  Admin
                          (auto)        ▼    │    │  Action
                                  ┌────────┐ │    │
                                  │ Locked │─┘    │
                                  └────────┘      │
                                   Unlock         ▼
                                            ┌───────────┐
                                            │ Suspended │
                                            └───────────┘
                                                  │
                                                  ▼
                                            ┌────────┐
                                            │ Closed │
                                            └────────┘
```

| Status | Meaning | Authentication Permitted |
|--------|---------|--------------------------|
| **Unverified** | Account created, Email Verification not completed | No |
| **Active** | Fully operational | Yes |
| **Locked** | Auto-locked due to excessive failed attempts. All Trusted Devices revoked. All Sessions terminated. | No |
| **Suspended** | Administratively disabled. All Sessions terminated. | No |
| **Closed** | Permanently deactivated. Identity persists. All Trusted Devices revoked. All Sessions terminated. | No |

---

## 5. Trusted Device Lifecycle

```
Successful Authentication + Opt-in
    │
    ▼
┌──────────────┐
│  Registered  │
└──────────────┘
    │         │
    ▼         ▼
┌─────────┐  ┌─────────┐
│ Revoked │  │ Expired │
└─────────┘  └─────────┘
```

| Trigger | Result |
|---------|--------|
| Person opts in after successful Authentication | Device → Registered |
| Person manually revokes | Device → Revoked |
| Admin revokes | Device → Revoked |
| Account Lockout | All Devices → Revoked (application layer orchestration) |
| Account Closed | All Devices → Revoked (application layer orchestration) |
| Trust period elapses | Device → Expired |

---

## 6. Recovery Request Lifecycle

```
Password Reset Requested
    │
    ▼
┌──────────┐     Verify        ┌──────────┐   Complete Reset   ┌───────────┐
│ Pending  │ ────────────────► │ Verified │ ──────────────────► │ Completed │
└──────────┘                   └──────────┘                     └───────────┘
    │
    ▼ (token expires)
┌──────────┐
│ Expired  │
└──────────┘
```

| Status | Meaning |
|--------|---------|
| **Pending** | Recovery Token issued and sent. Awaiting person to present it. |
| **Verified** | Recovery Token validated. Password reset is permitted. |
| **Completed** | Password successfully reset. Request is closed. |
| **Expired** | Recovery Token expired before use. |

---

## 7. Domain Events (30 total)

### Identity Events

| Event | When |
|-------|------|
| **Identity Created** | Registration (Identity aggregate created before Account) |

### Authentication Events

| Event | When |
|-------|------|
| **Authentication Succeeded** | All required factors verified in an Authentication Attempt |
| **Authentication Failed** | Invalid Credential presented during an Authentication Attempt |
| **Verification Code Generated** | MFA requires email/SMS code. Code generated within Authentication Attempt. Notification reacts to deliver it. |

### Account Lifecycle Events

| Event | When |
|-------|------|
| **Account Registered** | New Account created during Registration |
| **Email Verification Requested** | Registration. Signals that a verification link needs delivery via Notification. |
| **Email Verified** | Account transitioned from Unverified to Active |
| **Account Locked** | Excessive failed attempts. Trusted Devices revoked. Sessions terminated. |
| **Account Unlocked** | Restored from Locked to Active |
| **Account Suspended** | Administratively disabled. Sessions terminated. |
| **Account Closed** | Permanently deactivated. Trusted Devices revoked. Sessions terminated. |

### Credential Events

| Event | When |
|-------|------|
| **TOTP Secret Added** | TOTP credential added to Account |
| **TOTP Secret Removed** | TOTP credential removed from Account |
| **Recovery Codes Generated** | New batch of Recovery Codes added to Account |
| **Recovery Code Consumed** | Single-use Recovery Code used |
| **Password Changed** | Password replaced via Change Password behavior |
| **MFA Enabled** | Multi-Factor Authentication turned on for Account |
| **MFA Disabled** | Multi-Factor Authentication turned off for Account |
| **Password Reset Completed** | Password successfully replaced via Account Recovery. |

### Session & Token Events

| Event | When |
|-------|------|
| **Session Started** | New Session began following successful Authentication |
| **Session Ended** | Session ended via Logout, expiration, or forced termination (carries SessionEndReason) |
| **Refresh Token Rotated** | Refresh Token replaced with a new one during Session Refresh |

### Account Recovery Events

| Event | When |
|-------|------|
| **Password Reset Requested** | Person initiated Password Reset. Recovery Request created. |
| **Recovery Token Issued** | Recovery Token generated and sent via Notification. |
| **Recovery Token Verified** | Person presented valid Recovery Token. |
| **Recovery Request Completed** | Recovery Request marked as completed after password reset. |
| **Password Reset Expired** | Recovery Token expired before being used. |

### Trusted Device Events

| Event | When |
|-------|------|
| **Device Trusted** | Device registered as trusted for an Account |
| **Trusted Device Revoked** | Specific Trusted Device revoked (reason: MANUAL, ADMIN, LOCKOUT, CLOSURE, PASSWORD_CHANGED, MFA_RECONFIGURED, LIMIT_EXCEEDED) |
| **Trusted Device Expired** | Trust period elapsed |

---

## 8. Security Model

| Secret | Storage Method | Rationale |
|--------|---------------|-----------|
| **Password** | One-way hash (e.g., bcrypt, argon2) | Industry standard. Never needs to be read back. |
| **Refresh Token** | One-way hash | If DB compromised, hashed tokens cannot be used. Raw token only in consumer's hands. |
| **Recovery Token** | One-way hash | Same principle as Refresh Token. Protects during the recovery window. |
| **Recovery Codes** | One-way hash (each individually) | Raw codes shown once at generation, then only hashes retained. |
| **Verification Code** | One-way hash (within Authentication Attempt) | Short-lived but still hashed. Raw code only in person's email/SMS and in transit. |
| **TOTP Secret** | Encrypted at rest (symmetric encryption) | Must be readable for validation. Hashing would destroy the secret. Decrypted only at validation time. |
| **Access Token payload** | Not stored. Signed, not encrypted. | Contains only non-sensitive identifiers and timestamps. Signature prevents tampering. |

---

## 9. Invariants & Rules

| Rule | Description |
|------|-------------|
| Authentication is binary | No partial success. All required factors must pass before a Session or Token is created. |
| One Identity, one Account | An Identity has exactly one Account. A single person logs in one way; downstream contexts handle any role or tenant separation. |
| Identity survives Account closure | Closing an Account does not erase the Identity. Other contexts may still reference it. |
| Identity is its own aggregate | It persists independently with its own Repository. Created during Registration before the Account. |
| Account Recovery does not produce a Session | After Password Reset, the person must authenticate normally. |
| Recovery Token is not an Authentication Credential | It exists only within the Recovery Request aggregate and the Account Recovery process. |
| Only one active Recovery Request per Account | Creating a new one invalidates any previous pending request. |
| Verification Code is attempt-scoped | Generated on demand within an Authentication Attempt. Stored hashed. Expires with the attempt. Not a Credential on the Account. |
| Lockout revokes all Trusted Devices | Cascading side effect handled at the application layer. |
| Lockout terminates all Sessions | Cascading side effect handled at the application layer. |
| Closure revokes all Trusted Devices and terminates all Sessions | Cascading side effects handled at the application layer. |
| Suspension terminates all Sessions | Cascading side effect handled at the application layer. |
| Password Change terminates all Sessions | Cascading side effect handled at the application layer. Person must re-authenticate with new password. |
| Password Reset terminates all Sessions | Cascading side effect handled at the application layer. Person must authenticate normally after recovery. |
| Trusted Device relaxation is policy-driven | A Trusted Device **may** reduce MFA requirements. It does not automatically bypass them. |
| Maximum Trusted Devices per Account | Policy-defined. Enforced by the Enforce Device Limit domain service. |
| Password must satisfy Password Policy | Password Policy is external to Account (system-wide). Injected into Register, Change Password, and Reset Password behaviors. |
| Cannot remove the last Password credential | An Account must always have at least one Password. |
| MFA requires at least one non-Password credential | MFA can only be enabled when the Account has a TOTP Secret or Recovery Codes. |
| Access Token payload is non-sensitive | Contains only Identity ID, Account ID, Session ID, and timestamps. No secrets, credentials, or personal data. |
| Unverified Accounts cannot authenticate | Authentication is denied until Email Verification is completed. |
| Authentication Attempts are always recorded | Every attempt (success or failure) is tracked for Lockout and audit purposes. |
| Abandoned MFA attempts expire | An Authentication Attempt that is not completed within a defined period is discarded. |
| Access Tokens cannot be revoked | They are stateless and expire naturally. Only Refresh Tokens can be revoked. |
| Refresh Tokens are stored hashed | Never stored raw. If DB is compromised, tokens cannot be used. |

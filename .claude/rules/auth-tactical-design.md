# Authentication Service — Tactical Design

## Authentication Bounded Context (Core Domain)

---

## 1. Design Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Each credential type is modeled as its own specific Value Object | HashedPassword, EncryptedTOTPSecret, HashedRecoveryCode, HashedRecoveryCodeSet — type-safe, domain-meaningful, and self-validating. No generic Credential abstraction. |
| 2 | Supported credential types: Password, TOTP, Recovery Codes | Covers standard modern authentication. Additional types (Passkey/WebAuthn) can be added as new Value Objects without restructuring the aggregate. |
| 3 | Six aggregates: Identity, Account, Session, Trusted Device, Authentication Attempt, Recovery Request | Each has a distinct lifecycle and distinct consistency requirements. Cross-aggregate consistency is handled via domain events (eventual consistency). |
| 4 | Hybrid token storage: stateless Access Token, stateful Refresh Token | Access Token is self-contained (signed payload, not stored in DB, not part of any aggregate's state). Refresh Token is stored in DB in hashed form. Revocation targets the Refresh Token; the Access Token dies naturally on expiration. |
| 5 | All secrets stored securely | Passwords → hashed. Refresh Tokens → hashed. Recovery Tokens → hashed. Recovery Codes → hashed. Verification Codes → hashed. TOTP Secrets → encrypted at rest (must be readable for validation). Access Token payload → non-sensitive identifiers only. |
| 6 | Password Policy is external to Account | Password Policy is a system-wide rule, not owned by individual Accounts. It is injected as input into behaviors that need it (Register, Change Password, Reset Password). |
| 7 | Access Token is an application-layer output, not a domain concept | Access Token is stateless and never persisted. It is not modeled as a domain Value Object — it is built entirely in the application/infrastructure layer. The domain produces Sessions with Refresh Tokens; Access Token generation is orchestration. |
| 8 | Application Services orchestrate use cases, Domain Services contain cross-aggregate domain logic | Authenticate Identity and Recover Account are Application Services (orchestration). Terminate Sessions, Revoke Trusted Devices, and Enforce Device Limit are Domain Services (domain rules spanning aggregates). |
| 9 | Verification Code is generated within the Authentication Attempt | During MFA when a Possession Factor via email/SMS is required, the Authentication Attempt generates a temporary Verification Code (stored hashed internally), emits an event for delivery, and validates the code when presented. The code expires with the attempt. |

---

## 2. Value Objects

Value Objects are immutable, identity-less, and compared by their attributes.

| Value Object | Attributes | Invariants |
|-------------|------------|------------|
| **Identity ID** | Unique identifier (e.g., UUID) | Immutable. Set once at creation. Never changes. |
| **Account ID** | Unique identifier (e.g., UUID) | Immutable. Generated at Account creation. |
| **Email Address** | Address string | Must be a valid email format. Used as an identity claim for login. |
| **Account Status** | Enum: Unverified, Active, Locked, Suspended, Closed | Transitions governed by Account lifecycle rules (see §3). |
| **Authentication Factor** | Enum: Knowledge, Possession, Inherence | Categorizes credential types. Password → Knowledge. TOTP → Possession. Recovery Code → Knowledge. |
| **HashedPassword** | Hashed value | Stored as a one-way hash. Never stored in plain text. Must satisfy Password Policy at creation time. |
| **Password Policy** | Min length, max length, complexity rules, history depth (reuse prevention) | System-wide rule. Not owned by individual Accounts. Injected into behaviors that evaluate password validity. |
| **EncryptedTOTPSecret** | Encrypted shared secret | **Encrypted at rest** (not hashed) because the service must read the raw secret to validate TOTP codes. Decrypted only at validation time. Never stored in plain text. |
| **HashedRecoveryCode** | Hashed code value | **Stored as a one-way hash.** When presented, the input is hashed and compared. Single-use. |
| **HashedRecoveryCodeSet** | Collection of HashedRecoveryCodes | Generated as a batch. Raw codes shown to the person exactly once at generation time, then only hashes retained. Entire set replaced when regenerated. |
| **Hashed Password History** | Ordered list of previous password hashes | Used to enforce reuse restrictions in Password Policy. Max depth defined by policy. |
| **LockoutState** | count (0-100), lockout_count (0-50), last_failed_at, lockout_until | Tracks consecutive failures and tiered lockout escalation. Resets on successful authentication. Auto-unlocks when lockout_until expires. |
| **LockoutPolicy** | threshold (1-100), tier_minutes (tuple of positive ints, each ≤1440) | Configurable tiered lockout escalation. Injected into behaviors that evaluate lockout. |
| **LockReason** | Enum: THRESHOLD, ADMIN | Captures why an Account was locked. |
| **UnlockReason** | Enum: EXPIRY, ADMIN | Captures why an Account was unlocked. |
| **Verification Code** | Hashed code value, Expires At | **Stored as a one-way hash** within the Authentication Attempt. Short-lived (e.g., 5–10 minutes). Generated on demand during MFA when a Possession Factor via email/SMS is required. Raw value emitted via event for delivery. When the person presents the code, the input is hashed and compared. |
| **Hashed Verification Code** | Hashed string | Wraps the hashed value of a verification code. Guards against empty values. |
| **Device Fingerprint** | Device attributes hash | Immutable. Uniquely represents a device. |
| **Trusted Device Status** | Enum: Registered, Revoked, Expired | Transitions governed by Trusted Device lifecycle. |
| **Device Revocation Reason** | Enum: MANUAL, ADMIN, LOCKOUT, CLOSURE, PASSWORD_CHANGED, MFA_RECONFIGURED, LIMIT_EXCEEDED | Captures why a Trusted Device was revoked. Carried in the Trusted Device Revoked event. |
| **Device Policy** | max_devices (positive int) | Maximum number of Trusted Devices per Account. Enforced by EnforceDeviceLimit domain service. |
| **Session ID** | Unique identifier (e.g., UUID) | Immutable. Generated at Session creation. |
| **Session Status** | Enum: Active, Ended | Only two states. |
| **Session End Reason** | Enum: LOGOUT, IDLE_TIMEOUT, ABSOLUTE_TIMEOUT, FORCED, COMPROMISE | Captures why a Session was ended. Carried in the Session Ended event. |
| **Refresh Token** | Token hash, Expires At, Revoked flag | Longer-lived (days to weeks). Stateful — **stored in DB as a one-way hash** (never raw). Revocation is instant by marking as revoked or deleting. |
| **Attempt ID** | Unique identifier (e.g., UUID) | Immutable. Generated when attempt begins. |
| **Attempt Status** | Enum: In Progress, Succeeded, Failed, Expired | Transitions governed by Authentication Attempt lifecycle. |
| **Required Factors** | List of Authentication Factor types | Determined at attempt creation based on MFA configuration and Trusted Device status. |
| **Verified Factors** | List of Authentication Factor types verified so far | Internal bookkeeping. Not visible outside the aggregate. Starts empty. |
| **Recovery Request ID** | Unique identifier (e.g., UUID) | Immutable. Generated when a Password Reset is requested. |
| **Recovery Request Status** | Enum: Pending, Verified, Completed, Expired | Transitions governed by Recovery Request lifecycle. |
| **Recovery Token** | Token hash, Expires At | **Stored as a one-way hash** (never raw), same principle as Refresh Tokens. Single-use. For Account Recovery only. Not an Authentication Credential. |

---

## 3. Aggregates, Entities & Behaviors

---

### Aggregate 1: Identity

**Aggregate Root:** Identity (Entity)

This is a minimal aggregate. Its sole purpose is to exist as a persistent, immutable reference that outlives the Account and can be referenced by other bounded contexts.

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Identity** | Entity (Root) | The unique, immutable representation of a person or system. |
| **Identity ID** | Value Object | Unique identifier. Set at creation. Never changes. |

Identity has no behaviors beyond creation. It is created during Registration and never modified or deleted.

#### Domain Events Produced

| Event | Trigger |
|-------|---------|
| Identity Created | Registration (via `Identity.create()`, before Account creation) |

#### Domain Events Consumed

None.

---

### Aggregate 2: Account

**Aggregate Root:** Account (Entity)

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Account** | Entity (Root) | Central record. All external access goes through this. |
| **Account ID** | Value Object | Unique identifier for this Account. |
| **Identity ID** | Value Object | Immutable reference to the Identity this Account belongs to. |
| **Email Address** | Value Object | The identity claim used for login and verification. |
| **Account Status** | Value Object | Current lifecycle state. |
| **HashedPassword** | Value Object | Current password stored as a one-way hash. |
| **Hashed Password History** | Value Object | Previous password hashes for reuse prevention. |
| **EncryptedTOTPSecret** | Value Object (optional) | TOTP shared secret encrypted at rest. Null if TOTP not enabled. |
| **HashedRecoveryCodeSet** | Value Object | Batch of hashed single-use recovery codes. Empty set if none generated. |
| **LockoutState** | Value Object | Tracks consecutive failures, lockout tier, and locked_until timestamp for tiered lockout escalation. |
| **MFA Enabled** | Boolean | Whether Multi-Factor Authentication is required for this Account. Exposed as `is_mfa_enabled` property. |

Note: **Password Policy is not part of this aggregate.** It is a system-wide rule injected as input into behaviors that evaluate password validity.

#### Behaviors

| Behavior | Description | Preconditions | Postconditions |
|----------|-------------|---------------|----------------|
| **Register** | Classmethod factory. Creates a new Account with Identity ID, Email Address, and a HashedPassword. | Email must not already exist (via PreventDuplicateEmail domain service). Password must satisfy Password Policy (injected). | Account Status → Unverified. Password stored hashed. Account Registered event emitted. Email Verification Requested event emitted. |
| **Verify Email** | Transitions status from Unverified to Active. | Account must be Unverified. | Account Status → Active. Email Verified event emitted. |
| **Add TOTP Secret** | Stores an EncryptedTOTPSecret on the Account. | Account must be Active. Must not already have a TOTP secret (no duplicates). | TOTP secret stored. TOTP Secret Added event emitted. |
| **Remove TOTP Secret** | Removes the TOTP secret from the Account. | Account must be Active. TOTP secret must exist. Cannot remove if it's the last non-Password credential and MFA is enabled. | TOTP secret removed. TOTP Secret Removed event emitted. |
| **Add Recovery Codes** | Stores a new set of hashed recovery codes, replacing any existing set. | Account must be Active. | Recovery code set replaced. Recovery Codes Generated event emitted. |
| **Consume Recovery Code** | Marks a recovery code as used. | Account must be Active. Recovery code must exist and match. | Recovery code consumed. Recovery Code Consumed event emitted. Cannot remove if it's the last non-Password credential and MFA is enabled. |
| **Change Password** | Replaces the current HashedPassword with a new one. Adds old hash to history. | Account must be Active. New password must satisfy Password Policy (injected). Must not reuse a previous password (via PreventPasswordReuse domain service). | Old password replaced. New password stored hashed. History updated. Password Changed event emitted. |
| **Enable MFA** | Turns on Multi-Factor Authentication for the Account. | Account must be Active. At least one non-Password credential must exist (TOTP secret or Recovery Codes). MFA must not already be enabled. | MFA Enabled → true. MFA Enabled event emitted. |
| **Disable MFA** | Turns off Multi-Factor Authentication. | Account must be Active. MFA must be enabled. | MFA Enabled → false. MFA Disabled event emitted. |
| **Record Failed Attempt** | Increments LockoutState attempt count. If threshold reached (per LockoutPolicy), triggers Lock with tiered escalation. | Account must be Active. | LockoutState updated. If threshold reached: Account Status → Locked with tier-appropriate duration, Account Locked event emitted with LockReason. |
| **Record Successful Attempt** | Resets LockoutState (attempt count and tier). | Account must be Active. | LockoutState reset. |
| **Lock** | Transitions status to Locked with a LockReason. | Account must be Active. | Account Status → Locked. LockoutState updated with locked_until. Account Locked event emitted with LockReason. |
| **Unlock** | Transitions status from Locked to Active with an UnlockReason. Resets LockoutState. | Account must be Locked. For auto-unlock: locked_until must have expired. | Account Status → Active. LockoutState reset. Account Unlocked event emitted with UnlockReason. |
| **Suspend** | Transitions status to Suspended. | Account must be Active or Locked. | Account Status → Suspended. Account Suspended event emitted. |
| **Close** | Transitions status to Closed. Permanent. | Account must not already be Closed. | Account Status → Closed. Account Closed event emitted. |
| **Reset Password** | Replaces the HashedPassword as part of Account Recovery. Adds old hash to history. | New password must satisfy Password Policy (injected). | Old password replaced. New password stored hashed. History updated. Password Reset Completed event emitted. |

#### Domain Events Produced

| Event | Trigger |
|-------|---------|
| Account Registered | Register |
| Email Verification Requested | Register (signals that a verification link needs delivery) |
| Email Verified | Verify Email |
| TOTP Secret Added | Add TOTP Secret |
| TOTP Secret Removed | Remove TOTP Secret |
| Recovery Codes Generated | Add Recovery Codes |
| Recovery Code Consumed | Consume Recovery Code |
| Password Changed | Change Password |
| MFA Enabled | Enable MFA |
| MFA Disabled | Disable MFA |
| Account Locked | Lock (carries LockReason) |
| Account Unlocked | Unlock (carries UnlockReason) |
| Account Suspended | Suspend |
| Account Closed | Close |
| Password Reset Completed | Reset Password |

#### Domain Events Consumed

| Event | Source | Reaction |
|-------|--------|----------|
| Authentication Failed | Authentication Attempt | Record Failed Attempt |
| Authentication Succeeded | Authentication Attempt | Record Successful Attempt |

---

### Aggregate 3: Session

**Aggregate Root:** Session (Entity)

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Session** | Entity (Root) | Represents a period of authenticated access. |
| **Session ID** | Value Object | Unique identifier. |
| **Account ID** | Value Object | Reference to the Account this Session belongs to. |
| **Refresh Token** | Value Object | Stateful. Stored in DB as a one-way hash (never raw). Used to obtain new Access Tokens. Revoked by marking as revoked or deleting from DB. |
| **Session Status** | Value Object | Active or Ended. |

Note: **Access Token is not a domain concept.** It is a stateless, self-contained output built entirely in the application/infrastructure layer. The domain produces Sessions with Refresh Tokens; Access Token generation is orchestration.

#### Behaviors

| Behavior | Description | Preconditions | Postconditions |
|----------|-------------|---------------|----------------|
| **Start** | Classmethod factory. Creates a new Session with a Refresh Token. | Triggered only after Authentication succeeds. | Session Status → Active. Refresh Token stored. Session Started event emitted. |
| **Refresh** | Rotates the Refresh Token (replaces with new one). | Session must be Active. Refresh Token must be valid and not expired. | Old Refresh Token replaced with new one. Refresh Token Rotated event emitted. |
| **End** | Terminates the Session (voluntary logout). | Session must be Active. | Session Status → Ended. Session Ended event emitted with reason LOGOUT. |
| **Idle Timeout** | Terminates the Session due to inactivity. | Session must be Active. | Session Status → Ended. Session Ended event emitted with reason IDLE_TIMEOUT. |
| **Absolute Timeout** | Terminates the Session due to maximum lifetime reached. | Session must be Active. | Session Status → Ended. Session Ended event emitted with reason ABSOLUTE_TIMEOUT. |
| **Force End** | Terminates the Session due to external event (lockout, suspension, closure, password change). Used by Terminate Sessions domain service. | Session must be Active. | Session Status → Ended. Session Ended event emitted with reason FORCED. |
| **Flag Compromised** | Terminates the Session due to suspected compromise (e.g., refresh token reuse detection). | Session must be Active. | Session Status → Ended. Session Ended event emitted with reason COMPROMISE. |

#### Domain Events Produced

| Event | Trigger |
|-------|---------|
| Session Started | Start |
| Session Ended | End, Idle Timeout, Absolute Timeout, Force End, Flag Compromised (carries Session End Reason) |
| Refresh Token Rotated | Refresh |

#### Domain Events Consumed

| Event | Source | Reaction |
|-------|--------|----------|
| Authentication Succeeded | Authentication Attempt | Start (via application service) |
| Account Locked | Account | Force End all active Sessions via Terminate Sessions domain service. |
| Account Suspended | Account | Force End all active Sessions via Terminate Sessions domain service. |
| Account Closed | Account | Force End all active Sessions via Terminate Sessions domain service. |
| Password Changed | Account | Force End all active Sessions via Terminate Sessions domain service. Person must re-authenticate. |
| Password Reset Completed | Account | Force End all active Sessions via Terminate Sessions domain service. Person must authenticate normally after recovery. |

---

### Aggregate 4: Trusted Device

**Aggregate Root:** Trusted Device (Entity)

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Trusted Device** | Entity (Root) | A remembered device for a specific Account. |
| **Device ID** | Value Object | Unique identifier for this Trusted Device record. |
| **Account ID** | Value Object | Reference to the Account. |
| **Device Fingerprint** | Value Object | Uniquely identifies the physical device. |
| **Trusted Device Status** | Value Object | Registered, Revoked, or Expired. |
| **Expires At** | datetime | When the trust period for this device ends. Checked by Is Trusted query. |

#### Behaviors

| Behavior | Description | Preconditions | Postconditions |
|----------|-------------|---------------|----------------|
| **Register** | Creates a new Trusted Device. | Account must be Active. Person must opt in after successful Authentication. Maximum device limit must not be exceeded (checked by Enforce Device Limit domain service). | Status → Registered. Device Trusted event emitted. |
| **Revoke** | Ends trust for this device. Accepts a Device Revocation Reason. | Status must be Registered. | Status → Revoked. Trusted Device Revoked event emitted with reason. |
| **Expire** | Auto-transitions when trust period elapses. | Status must be Registered. | Status → Expired. Trusted Device Expired event emitted. |
| **Is Trusted** | Checks whether this device is currently valid (Registered and not expired). | Read-only. No state change. | Returns true or false. |

#### Domain Events Produced

| Event | Trigger |
|-------|---------|
| Device Trusted | Register |
| Trusted Device Revoked | Revoke |
| Trusted Device Expired | Expire |

#### Domain Events Consumed

| Event | Source | Reaction |
|-------|--------|----------|
| Account Locked | Account | Revoke all Trusted Devices for that Account via Revoke Trusted Devices domain service (reason=LOCKOUT) |
| Account Closed | Account | Revoke all Trusted Devices for that Account via Revoke Trusted Devices domain service (reason=CLOSURE) |

---

### Aggregate 5: Authentication Attempt

**Aggregate Root:** Authentication Attempt (Entity)

A short-lived aggregate that models a single login attempt from start to finish. It tracks multi-factor authentication progress, stores and validates verification codes for email/SMS MFA, and enforces its own time-based expiration. The aggregate does **not** validate credentials (passwords, TOTP) — that is delegated to the Account aggregate via the application service. The Attempt only tracks which factors have been satisfied. The aggregate is pure — it receives plain values (`now: datetime`, pre-hashed value objects) and never depends on infrastructure services.

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Authentication Attempt** | Entity (Root) | A single attempt to verify an Identity. Short-lived. |
| **Attempt ID** | Value Object | Unique identifier. |
| **Account ID** | Value Object | Reference to the Account being authenticated. |
| **Attempt Status** | Value Object | In Progress, Succeeded, Failed, or Expired. |
| **Required Factors** | Value Object | Authentication Factor categories required. Immutable tuple with guards against empty or duplicate values. Has `is_satisfied_by(verified)` query. |
| **Verified Factors** | Value Object | Factors verified so far. Internal only. Immutable — creates new instances when factors are added. Has `fresh()`, `has_factor()`, and `with_factor()` methods. |
| **Hashed Verification Code** | Value Object | Wraps the hashed string of a verification code. Guards against empty values. |
| **Verification Code** | Value Object | Hashed one-time code for Possession Factor verification via email/SMS. Null if not yet generated or not needed. Constructed by the application layer (which handles token generation and hashing) and passed to the aggregate. Raw value emitted via event for delivery. Has its own `expires_at` timestamp (shorter than the attempt's lifetime). Has `is_expired(now)` and `matches(hashed_code)` query methods. |
| **Expires At** | datetime | When this attempt expires. Set at creation by the factory. Used by guards to reject operations on expired attempts. |

#### Behaviors

| Behavior | Description | Preconditions | Postconditions |
|----------|-------------|---------------|----------------|
| **Initiate** | Classmethod that creates a new attempt. Receives pre-determined Required Factors and an expiration timestamp from the factory. | None (factory ensures validity). | Status → In Progress. Required Factors set. Verified Factors empty. Verification Code null. |
| **Set Verification Code** | Stores a pre-built `VerificationCode` value object for Possession Factor via email/SMS. Accepts `verification_code` (VerificationCode), `raw_code` (str, for the domain event), and `now` (datetime). The application layer handles token generation and hashing. | Status must be In Progress. Attempt must not be expired. Required Factors must include Possession. No existing unexpired code (expired code allows regeneration). | Verification Code stored. Verification Code Generated event recorded (carries raw code and account ID). |
| **Verify Factor** | Records that a factor has been externally validated by the application layer. Used for all factors — Knowledge (password validated via Account), Possession (TOTP or verification code validated externally). The application layer retrieves the stored `verification_code` property, hashes the presented code, compares, and calls this method if valid. Accepts `factor` and `now` (datetime). | Status must be In Progress. Attempt must not be expired. Factor must be required. Factor must not already be verified. | Verified Factors updated. If all factors verified: Status → Succeeded, Authentication Succeeded event recorded. |
| **Fail** | Marks the attempt as failed due to invalid Credential. | Status must be In Progress. | Status → Failed. Authentication Failed event recorded. |
| **Expire** | Transitions to Expired when the time limit has been reached. Accepts `now` (datetime). | Status must be In Progress. `now >= expires_at` must be true. | Status → Expired. No downstream event — expired attempts are silently discarded. |

#### Query Methods

| Method | Description |
|--------|-------------|
| **is_expired(now)** | Returns `True` if `now >= expires_at`. Does not mutate state. |

#### Guards

| Guard | Raises | Description |
|-------|--------|-------------|
| **_guard_is_in_progress** | AttemptNotInProgressError | Attempt must be In Progress. |
| **_guard_not_expired** | AttemptExpiredError | Attempt must not have passed its `expires_at`. Accepts `now` (datetime). |
| **_guard_is_expired** | AttemptNotExpiredError | Attempt must have passed its `expires_at`. Used by `expire()`. Accepts `now` (datetime). |
| **_guard_factor_is_required** | FactorNotRequiredError | Factor must be in Required Factors. |
| **_guard_factor_not_already_verified** | FactorAlreadyVerifiedError | Factor must not already be in Verified Factors. |
| **_guard_requires_possession_factor** | FactorNotRequiredError | Required Factors must include Possession. |
| **_guard_verification_code_not_already_generated** | VerificationCodeAlreadyGeneratedError | No existing unexpired code. Accepts `now` (datetime). Expired code allows regeneration. |

#### Errors

| Error | Message |
|-------|---------|
| AttemptNotInProgressError | Authentication attempt is not in progress. |
| AttemptExpiredError | Authentication attempt has expired. |
| AttemptNotExpiredError | Authentication attempt has not yet expired. |
| FactorNotRequiredError | The provided factor is not required for this attempt. |
| FactorAlreadyVerifiedError | The provided factor has already been verified. |
| VerificationCodeAlreadyGeneratedError | A verification code has already been generated for this attempt. |

#### Key Design Decisions

- **Delegation model:** The Attempt does not validate credentials (passwords, TOTP, verification codes). The application layer performs all validation — hashing, comparing, verifying — and then tells the Attempt whether the factor passed (`verify_factor()`) or failed (`fail()`). This keeps the aggregate pure and decoupled from infrastructure services.
- **Unified factor verification:** All factors go through `verify_factor()`. There is no separate code path for verification codes — the application layer retrieves the stored `verification_code`, hashes the presented code, compares, and calls `verify_factor(POSSESSION)` if valid. This follows the same pattern as password validation on the Account aggregate.
- **Hashing is orchestration:** Token generation, hashing, and verification are application layer concerns. The aggregate receives pre-built value objects (`VerificationCode`) and `now: datetime` — never infrastructure services.
- **Aggregate owns `expires_at`:** The expiration timestamp is set at creation and checked in guards. The aggregate enforces its own time-based invariants rather than relying on external schedulers.

#### Key Rules

- Authentication is **all-or-nothing.** Verified Factors is internal bookkeeping only. No external system can see partial progress. The only visible outcomes are: Succeeded, Failed, or Expired.
- The Verification Code is **temporary and attempt-scoped.** It exists only within this attempt, is stored hashed, and expires independently (shorter than the attempt). It is never reused across attempts.
- The Verification Code is **not a Credential on the Account.** It is generated and consumed entirely within the Authentication Attempt's lifecycle.
- The `fail()` behavior does not carry a `failed_factor` — the application service knows which factor failed. The Authentication Failed event contains only the attempt ID and account ID.

#### Domain Events Produced

| Event | Fields | Trigger |
|-------|--------|---------|
| Verification Code Generated | attempt_id, account_id | Set Verification Code |
| Authentication Succeeded | attempt_id, account_id, factors_used | Verify Factor or Verify Verification Code (all factors satisfied) |
| Authentication Failed | attempt_id, account_id | Fail (invalid credential) |

#### Domain Events Consumed

None. This aggregate is always created fresh and lives only until it completes or expires.

---

### Aggregate 6: Recovery Request

**Aggregate Root:** Recovery Request (Entity)

#### Structure

| Element | Type | Description |
|---------|------|-------------|
| **Recovery Request** | Entity (Root) | A single Password Reset request. Short-lived. |
| **Recovery Request ID** | Value Object | Unique identifier. |
| **Account ID** | Value Object | Reference to the Account requesting recovery. |
| **Recovery Token** | Value Object | Stored as a one-way hash (never raw). Sent to the person via the Notification context. When presented, the input is hashed and compared. |
| **Recovery Request Status** | Value Object | Pending, Verified, Completed, or Expired. |

#### Behaviors

| Behavior | Description | Preconditions | Postconditions |
|----------|-------------|---------------|----------------|
| **Create** | Initiates a new Recovery Request. Generates a Recovery Token (hashed for storage, raw value returned once for delivery). | Account must exist. Any previous pending Recovery Requests for the same Account should be expired/invalidated. | Status → Pending. Recovery Token hash stored. Password Reset Requested and Recovery Token Issued events emitted. |
| **Verify** | Validates the presented Recovery Token. | Status must be Pending. Token must not be expired. | Status → Verified. Recovery Token Verified event emitted. |
| **Complete** | Marks the Recovery Request as completed after the Account has successfully reset its password. | Status must be Verified. | Status → Completed. Recovery Request Completed event emitted. |
| **Expire** | Auto-transitions when the token expiration time is reached. | Status must not be Completed or Expired. | Status → Expired. Password Reset Expired event emitted. |

#### Key Rules

- A Recovery Request is **single-use.** Once the token is verified and the password is reset, the request is completed and cannot be reused.
- Only **one active Recovery Request** per Account at a time. Creating a new one invalidates any previous pending request.
- The Recovery Token is **not an Authentication Credential.** It exists only within the Account Recovery process and is never used for login.

#### Domain Events Produced

| Event | Trigger |
|-------|---------|
| Password Reset Requested | Create |
| Recovery Token Issued | Create |
| Recovery Token Verified | Verify |
| Recovery Request Completed | Complete |
| Password Reset Expired | Expire |

#### Domain Events Consumed

None. Recovery Requests are created by the Recover Account application service and follow their own lifecycle.

---

## 4. Repositories

One Repository per Aggregate Root. The domain defines the interface — the implementation lives outside the domain.

| Repository | Aggregate Root | Key Operations |
|-----------|----------------|----------------|
| **Identity Repository** | Identity | Find by Identity ID. Save. |
| **Account Repository** | Account | Find by Account ID. Find by Email Address. Find by Identity ID. Save. |
| **Session Repository** | Session | Find by Session ID. Find all active Sessions by Account ID. Find by Refresh Token hash. Save. |
| **Trusted Device Repository** | Trusted Device | Find by Device ID. Find all by Account ID. Find by Account ID and Device Fingerprint. Count by Account ID (for max device limit). Save. |
| **Authentication Attempt Repository** | Authentication Attempt | Find by Attempt ID. Save. Delete expired attempts (cleanup). |
| **Recovery Request Repository** | Recovery Request | Find by Recovery Request ID. Find pending request by Account ID. Find by Recovery Token hash. Save. Delete expired requests (cleanup). |

---

## 5. Application Services

Application Services orchestrate use cases. They fetch aggregates from repositories, call behaviors on them, save results, and coordinate event flow. They contain **no domain logic** — they delegate to aggregates and domain services.

### Authenticate Identity

**Purpose:** Orchestrates the full authentication use case.

| Step | Description |
|------|-------------|
| 1 | Receives Login request (Email Address + Credential). |
| 2 | Looks up Account by Email Address via Account Repository. |
| 3 | Checks Account Status (must be Active). |
| 4 | Checks Trusted Device status via Trusted Device Repository (finds by Account ID and Device Fingerprint). |
| 5 | Determines Required Factors based on MFA configuration and Trusted Device status. Creates an Authentication Attempt via `AuthenticationAttempt.initiate()` (passing Account ID and Required Factors). |
| 6 | Calls Validate Credential on the Account for the Knowledge Factor (hashes input and compares for Password). |
| 7 | If valid: calls Verify Factor on the Attempt for the Knowledge Factor (passing Clock). |
| 8 | If MFA required and Possession Factor needed via email/SMS: calls Generate Verification Code on the Attempt (passing TokenGenerator, TokenHasher, Clock, code_expires_at) → Verification Code Generated event → Notification delivers the code. Waits for person to present the code. Calls Verify Verification Code on the Attempt (passing raw_code, TokenHasher, Clock). |
| 8b | If MFA required and Possession Factor via TOTP: calls Validate Credential on the Account for TOTP → if valid: calls Verify Factor on the Attempt for the Possession Factor (passing Clock). |
| 9 | If all factors verified: Authentication Succeeded event → Account reacts (reset counter), `Session.start()` creates Session. Application layer generates Access Token separately. |
| 10 | If invalid at any step: calls Fail on the Attempt → Authentication Failed event → Account reacts (increment counter, potentially Lock). |

### Recover Account

**Purpose:** Orchestrates the Password Reset use case.

| Operation | Steps |
|-----------|-------|
| **Request Password Reset** | 1. Receives request with Email Address. 2. Looks up Account via Account Repository. 3. Invalidates any existing pending Recovery Request via Recovery Request Repository. 4. Creates a new Recovery Request via `RecoveryRequest.create()` (Recovery Token hash stored). 5. Password Reset Requested and Recovery Token Issued events emitted (Notification reacts to deliver the raw token). |
| **Verify Recovery Token** | 1. Receives the raw Recovery Token. 2. Hashes it and looks up the Recovery Request by token hash via Recovery Request Repository. 3. Calls Verify on the Recovery Request. 4. Recovery Token Verified event emitted. |
| **Complete Password Reset** | 1. Receives new Password and Recovery Request ID. 2. Looks up Recovery Request via Recovery Request Repository. 3. Confirms Recovery Request is in Verified status. 4. Looks up Account via Account Repository. 5. Calls Reset Password on the Account (Password Policy injected). 6. Calls Complete on the Recovery Request. 7. Password Reset Completed event emitted by Account. |

---

## 6. Domain Services

Domain Services contain **domain logic that spans multiple aggregates** — cross-aggregate invariants and rules. They are not orchestrators; they express domain rules.

### PreventPasswordReuse

**Purpose:** Domain rule: a new password must not match the current password or any in the password history.

| Operation | Description |
|-----------|-------------|
| **check** | `@classmethod`. Accepts raw password (`str`), current `HashedPassword`, `HashedPasswordHistory`, and a password hash verifier callable (`Callable[[str, HashedPassword], bool]`). Raises `PasswordReuseError` if the password matches the current or any historical hash. |

### PreventDuplicateEmail

**Purpose:** Domain rule: email addresses must be unique across accounts.

| Operation | Description |
|-----------|-------------|
| **check** | `@classmethod`. Async. Accepts `EmailAddress` and `AccountRepository`. Raises `EmailAlreadyTakenError` if an account with that email already exists. |

### EnforceDeviceLimit

**Purpose:** Domain rule: an Account cannot exceed the maximum number of Trusted Devices.

| Operation | Description |
|-----------|-------------|
| **check** | `@classmethod`. Async. Accepts `AccountId`, `DevicePolicy`, and `TrustedDeviceRepository`. Counts current active devices for the Account. If at or above the policy maximum, raises `DeviceLimitExceededError`. Called before `TrustedDevice.register()`. |

### Terminate Sessions (not yet implemented)

**Purpose:** Domain rule: when an Account is locked, suspended, or closed, all its active Sessions must end. Currently handled at the application layer.

### Revoke Trusted Devices (not yet implemented)

**Purpose:** Domain rule: when an Account is locked or closed, all its Trusted Devices must be revoked. Currently handled at the application layer.

---

## 7. Factories

Factories ensure aggregates are born in a valid state. In this project, factories are implemented as **classmethod factories on the aggregate itself**, not as separate factory classes. Infrastructure-dependent creation logic (hashing, ID generation) is handled by the application layer before calling the factory.

| Aggregate | Factory Method | Description |
|-----------|---------------|-------------|
| **Identity** | `Identity.create()` | Accepts Identity ID. Returns a new Identity with Identity Created event. |
| **Account** | `Account.register()` | Accepts Account ID, Identity ID, Email Address, HashedPassword, and HashedPasswordHistory. Returns a new Account in Unverified status with Account Registered and Email Verification Requested events. |
| **Session** | `Session.start()` | Accepts Session ID, Account ID, and Refresh Token. Returns a new Session in Active status with Session Started event. |
| **Authentication Attempt** | `AuthenticationAttempt.initiate()` | Accepts Attempt ID, Account ID, Required Factors, and expires_at. Returns a new Attempt in In Progress status. Verification Code is not generated at creation — it is set on demand via the Set Verification Code behavior. |
| **Recovery Request** | `RecoveryRequest.create()` | Accepts Recovery Request ID, Account ID, and Recovery Token. Returns a new Recovery Request in Pending status with Password Reset Requested and Recovery Token Issued events. |
| **Trusted Device** | `TrustedDevice.register()` | Accepts Device ID, Account ID, Device Fingerprint, and expires_at. Returns a new Trusted Device in Registered status with Device Trusted event. |

---

## 8. Security Model Summary

| Secret | Storage Method | Rationale |
|--------|---------------|-----------|
| **Password** | One-way hash (e.g., bcrypt, argon2) | Industry standard. Never needs to be read back. |
| **Refresh Token** | One-way hash | If DB is compromised, hashed tokens cannot be used. Raw token only exists in consumer's hands. |
| **Recovery Token** | One-way hash | Same principle as Refresh Token. Protects against DB compromise during the recovery window. |
| **Recovery Codes** | One-way hash (each code individually) | Same principle as passwords. Raw codes shown once at generation, then only hashes retained. |
| **Verification Code** | One-way hash (within Authentication Attempt) | Short-lived but still hashed. If the Attempt repository is compromised, codes cannot be extracted. Raw code only exists in the person's email/SMS and in transit. |
| **TOTP Secret** | Encrypted at rest (symmetric encryption) | Must be readable for TOTP code validation. Hashing would destroy the secret. Encryption protects at rest while allowing decryption at validation time. |
| **Access Token payload** | Not stored. Signed, not encrypted. Application-layer concern. | Contains only non-sensitive identifiers (Identity ID, Account ID, Session ID) and timestamps. No secrets, credentials, or personal data. Signature prevents tampering. Not a domain Value Object. |

---

## 9. Cross-Aggregate Event Flow (Complete)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AUTHENTICATION ATTEMPT                        │
│                                                                      │
│  Initiate                                                            │
│    → Verify Knowledge Factor (Password)                              │
│    → If MFA via email/SMS: Generate Verification Code                │
│        → Verification Code Generated event → Notification delivers   │
│        → Person presents code → Verify Possession Factor             │
│    → If MFA via TOTP: Verify Possession Factor (TOTP)               │
│    → All factors verified → Succeeded                                │
│    → Invalid credential at any step → Failed                         │
└──────────────────┬──────────────────────┬────────────────────────────┘
                   │                      │
    Authentication Succeeded     Authentication Failed
                   │                      │
          ┌────────┴────────┐             │
          ▼                 ▼             ▼
   ┌─────────────┐  ┌──────────┐  ┌─────────────┐
   │   SESSION   │  │ ACCOUNT  │  │   ACCOUNT   │
   │   (Create)  │  │ (Reset   │  │ (Increment  │
   │             │  │ counter) │  │  counter)   │
   └─────────────┘  └──────────┘  └──────┬──────┘
                                         │
                              ┌──────────┴──────────┐
                              │ Threshold reached?   │
                              │                      │
                              ▼ Yes                  ▼ No
                    ┌──────────────┐          (no further
                    │ Account      │           action)
                    │ Locked       │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼                         ▼
   ┌─────────────────┐      ┌────────────────────┐
   │ Terminate        │      │ Revoke Trusted      │
   │ Sessions         │      │ Devices             │
   │ (force_end on    │      │                     │
   │  each session)   │      │                     │
   └─────────────────┘      └────────────────────┘


Account Suspended ──────► Terminate Sessions
Account Closed ─────────► Terminate Sessions + Revoke Trusted Devices


┌─────────────────────────────────────────────────────────────────────┐
│                        ACCOUNT RECOVERY FLOW                         │
│                                                                      │
│  Request Password Reset                                              │
│    → Recovery Request Created (token hashed and stored)              │
│    → Recovery Token Issued event → Notification delivers raw token   │
│                                                                      │
│  Person presents raw token                                           │
│    → Token hashed and compared → Recovery Request Verified           │
│                                                                      │
│  Person submits new password                                         │
│    → Account.Reset Password (new password hashed, policy injected)   │
│    → Recovery Request Completed                                      │
│    → Person must now authenticate normally (no Session created)       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 10. Complete Model Summary

### Aggregates (6 total)

| Aggregate | Root Entity | Purpose |
|-----------|-------------|---------|
| Identity | Identity | Immutable reference. Persists beyond Account. Referenced by other bounded contexts. |
| Account | Account | Stateful record of an Identity. Holds HashedPassword, EncryptedTOTPSecret, HashedRecoveryCodeSet. Central to all operations. |
| Session | Session | Time-bound authenticated access. Holds Refresh Token (stateful). |
| Trusted Device | Trusted Device | Remembered device that may relax MFA. |
| Authentication Attempt | Authentication Attempt | Short-lived attempt to verify an Identity. Generates and validates Verification Codes for email/SMS MFA. |
| Recovery Request | Recovery Request | Short-lived Password Reset request. Owns the Recovery Token. |

### Value Objects (31 total)

| Category | Value Objects |
|----------|--------------|
| Identity & Account | Identity ID, Account ID, Email Address, Account Status |
| Credentials | Authentication Factor, HashedPassword, Password Policy (external, injected), EncryptedTOTPSecret, HashedRecoveryCode, HashedRecoveryCodeSet, Hashed Password History |
| Security | LockoutState, LockoutPolicy, LockReason, UnlockReason, Verification Code (hashed, attempt-scoped), HashedVerificationCode |
| Session & Token | Session ID, Session Status, Session End Reason, Refresh Token (hashed) |
| Trusted Device | Device Fingerprint, Trusted Device Status, Device Revocation Reason |
| Authentication Attempt | Attempt ID, Attempt Status, Required Factors, Verified Factors |
| Account Recovery | Recovery Request ID, Recovery Request Status, Recovery Token (hashed) |

### Domain Events (30 total)

| Category | Events |
|----------|--------|
| Identity | Identity Created |
| Authentication | Authentication Succeeded, Authentication Failed, Verification Code Generated |
| Account Lifecycle | Account Registered, Email Verification Requested, Email Verified, Account Locked, Account Unlocked, Account Suspended, Account Closed |
| Credentials | TOTP Secret Added, TOTP Secret Removed, Recovery Codes Generated, Recovery Code Consumed, Password Changed, MFA Enabled, MFA Disabled, Password Reset Completed |
| Session | Session Started, Session Ended, Refresh Token Rotated |
| Account Recovery | Password Reset Requested, Recovery Token Issued, Recovery Token Verified, Recovery Request Completed, Password Reset Expired |
| Trusted Device | Device Trusted, Trusted Device Revoked, Trusted Device Expired |

### Repositories (6 total)

| Repository | Root |
|-----------|------|
| Identity Repository | Identity |
| Account Repository | Account |
| Session Repository | Session |
| Trusted Device Repository | Trusted Device |
| Authentication Attempt Repository | Authentication Attempt |
| Recovery Request Repository | Recovery Request |

### Application Services (2 total)

| Service | Purpose |
|---------|---------|
| Authenticate Identity | Orchestrates the full login use case (including MFA with Verification Code generation and delivery) |
| Recover Account | Orchestrates the Password Reset use case |

### Domain Services (5 total, 2 not yet implemented)

| Service | Purpose |
|---------|---------|
| PreventPasswordReuse | Domain rule: new password must not match current or historical passwords |
| PreventDuplicateEmail | Domain rule: email addresses must be unique across accounts |
| EnforceDeviceLimit | Domain rule: Account cannot exceed max Trusted Devices (accepts DevicePolicy) |
| Terminate Sessions | Domain rule: locked/suspended/closed Account → end all Sessions (not yet implemented) |
| Revoke Trusted Devices | Domain rule: locked/closed Account → revoke all devices (not yet implemented) |

### Factories (6 total — classmethod factories on aggregates)

| Aggregate | Factory Method |
|-----------|---------------|
| Identity | `Identity.create()` |
| Account | `Account.register()` |
| Session | `Session.start()` |
| Authentication Attempt | `AuthenticationAttempt.initiate()` |
| Recovery Request | `RecoveryRequest.create()` |
| Trusted Device | `TrustedDevice.register()` |

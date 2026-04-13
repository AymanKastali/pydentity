# Authentication Context (Core Domain)

Account lifecycle, credential management, session handling, device tracking, and verification flows. This is the reason the system exists — highest investment, deepest modeling, most rigorous design.

---

## Aggregates

### Account

**Identity:** `AccountId` (UUID)
**Internal Entity:** `EmailPasswordCredential` (shares password history invariant with root)

**Status state machine:**

```
PENDING_VERIFICATION --> ACTIVE         [verify_email]
ACTIVE               --> LOCKED         [lock]
ACTIVE               --> SUSPENDED      [suspend]
ACTIVE               --> CLOSED         [close]
LOCKED               --> ACTIVE         [unlock]
```

**Key invariants:**
- Password cannot repeat any entry in password history (depth from `PasswordPolicy`)
- Failed attempt count exceeding `LockoutPolicy` threshold triggers automatic lock
- Email must be unique across all accounts (via `PreventDuplicateEmail` domain service)
- New password must not appear in breach databases (NIST 800-63B)
- New password must satisfy `PasswordPolicy` length constraints

**Behaviors (pure — no infrastructure params):** `create`, `record_login_success()`, `record_login_failure(lockout_policy)`, `verify_email`, `change_password(new_hash, max_history)`, `change_email(new_email)`, `lock`, `unlock`, `suspend`, `close`

**Events produced:** `AccountRegistered`, `LoginSucceeded`, `LoginFailed`, `EmailVerified`, `EmailChanged`, `PasswordChanged`, `AccountLocked`, `AccountUnlocked`, `AccountSuspended`, `AccountClosed`

### Session

**Identity:** `SessionId` (UUID)
**References by ID:** `AccountId`, `DeviceId`

**Key invariants:**
- Can only be revoked or refreshed when status is `ACTIVE`
- Expiration is extended (not shortened) on refresh

**Behaviors:** `create`, `revoke`, `refresh`

**Events produced:** `SessionStarted`, `SessionRevoked`, `SessionRefreshed`

### Device

**Identity:** `DeviceId` (UUID)
**References by ID:** `AccountId`

**Key invariants:**
- Can only be revoked when status is `ACTIVE`
- Active device count per account must not exceed `DevicePolicy.max_devices_per_account` (via `RegisterDevice` domain service)

**Behaviors:** `create`, `revoke`

**Events produced:** `DeviceRegistered`, `DeviceRevoked`

### VerificationRequest

**Identity:** `VerificationRequestId` (UUID)
**References by ID:** `AccountId`

**Status state machine:**

```
PENDING --> VERIFIED      [verify (success)]
PENDING --> INVALIDATED   [invalidate]
PENDING --> EXPIRED       [expire]
```

**Key invariants:**
- Token can only be verified when status is `PENDING`
- Verification rejects expired requests (checked against expiry)
- Verification rejects invalid tokens (via `VerificationRequestTokenVerifier`)
- Pending requests are invalidated when a new request of the same type is created for the same account

**Behaviors (pure — no infrastructure params):** `create`, `verify`, `invalidate`, `expire`

**Events produced:** `VerificationRequestCreated`, `VerificationRequestVerified`, `VerificationRequestFailed`, `VerificationRequestInvalidated`, `VerificationRequestExpired`

---

## Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| `CredentialId` | `value: UUID` | Identifies a credential entity |
| `Email` | `value: str` | Validated email address |
| `RawPassword` | `value: str` | Plaintext password (transient, never persisted) |
| `HashedPassword` | `value: str` | Cryptographically hashed password |
| `FailedAttemptCount` | `value: int` | Consecutive failed login attempts |
| `PasswordPolicy` | `min_length, max_length, max_history: int` | Password requirements |
| `LockoutPolicy` | `max_failed_attempts, lockout_duration_seconds: int` | Lockout thresholds |
| `SessionId` | `value: UUID` | Identifies a session |
| `SessionPolicy` | `ttl_seconds: int` | Session duration configuration |
| `SessionExpiry` | `value: datetime` | When a session expires |
| `RawDeviceFingerprint` | `value: str` | Plaintext fingerprint (transient, never persisted) |
| `HashedDeviceFingerprint` | `value: str` | Hashed fingerprint |
| `DevicePolicy` | `max_devices_per_account: int` | Device limit per account |
| `VerificationRequestId` | `value: UUID` | Identifies a verification request |
| `RawVerificationRequestToken` | `value: str` | Plaintext token (transient, never persisted) |
| `HashedVerificationRequestToken` | `value: str` | Hashed token |
| `VerificationPolicy` | `email_verification_ttl_seconds, password_reset_ttl_seconds: int` | TTL per request type |
| `VerificationRequestExpiry` | `value: datetime` | When a verification request expires |

## Enums

| Name | Values |
|------|--------|
| `AccountStatus` | `PENDING_VERIFICATION`, `ACTIVE`, `LOCKED`, `SUSPENDED`, `CLOSED` |
| `LockReason` | `THRESHOLD`, `ADMIN` |
| `UnlockReason` | `EXPIRY`, `ADMIN` |
| `SessionStatus` | `ACTIVE`, `REVOKED` |
| `SessionRevocationReason` | `LOGOUT`, `EXPIRED`, `FORCED`, `COMPROMISE` |
| `DeviceStatus` | `ACTIVE`, `REVOKED` |
| `DeviceRevocationReason` | `MANUAL`, `ADMIN`, `LOCKOUT`, `CLOSURE` |
| `VerificationRequestStatus` | `PENDING`, `VERIFIED`, `INVALIDATED`, `EXPIRED` |
| `VerificationRequestType` | `EMAIL_VERIFICATION`, `PASSWORD_RESET` |
| `VerificationFailureReason` | `INVALID_TOKEN`, `EXPIRED`, `ALREADY_VERIFIED` |

---

## Domain Interfaces

| Name | Method | Purpose |
|------|--------|---------|
| `PasswordHasher` | `hash(password) -> HashedPassword` | Hashes a raw password |
| `PasswordVerifier` | `verify(password, hash) -> bool` | Verifies password against hash |
| `CompromisedPasswordChecker` | `is_compromised(password) -> bool` | Checks breach databases (NIST 800-63B) |
| `EmailVerifier` | `is_valid(email) -> bool` | Validates email address format |
| `DeviceFingerprintHasher` | `hash(fingerprint) -> HashedDeviceFingerprint` | Hashes a device fingerprint |
| `DeviceFingerprintVerifier` | `verify(fingerprint, hash) -> bool` | Verifies fingerprint against hash |
| `VerificationRequestTokenHasher` | `hash(token) -> HashedVerificationRequestToken` | Hashes a verification token |
| `VerificationRequestTokenVerifier` | `verify(token, hash) -> bool` | Verifies token against hash |

## Domain Services

| Name | Purpose |
|------|---------|
| `PreventDuplicateEmail` | Injected: `AccountRepository`. Ensures email uniqueness via `ensure_unique(email)`. |
| `AuthenticateAccount` | Injected: `AccountRepository`, `PasswordVerifier`. Finds account by email, verifies credentials. Raises `InvalidCredentialsError` for both missing account and wrong password (no information leakage). Returns `Account` — caller handles `record_login_success`/`record_login_failure`. |
| `ChangeAccountPassword` | Injected: `PasswordVerifier`, `PasswordHasher`, `CompromisedPasswordChecker`. Validates current password, policy, breach check, reuse check. Returns `HashedPassword` — caller applies `Account.change_password`. |
| `ChangeAccountEmail` | Injected: `EmailVerifier`, `PreventDuplicateEmail`. Validates email format and uniqueness. Caller applies `Account.change_email`. |
| `RegisterAccount` | Injected: `EmailVerifier`, `PasswordHasher`, `CompromisedPasswordChecker`, `PreventDuplicateEmail`. Validates email, password policy, breach check, email uniqueness, hashes, delegates to `Account.create`. |
| `RevokeSessions` | Injected: `SessionRepository`. Revokes all active sessions for a device. |
| `RegisterDevice` | Injected: `DeviceFingerprintHasher`, `DeviceRepository`. Registers a device, enforcing max device limit. |
| `RevokeDevices` | Injected: `DeviceRepository`. Revokes all active devices for an account. |
| `IssueEmailVerificationRequest` | Injected: `VerificationRequestTokenHasher`, `VerificationRequestRepository`. Invalidates existing pending email verification, hashes token, computes expiry, delegates to `VerificationRequest.create()`. |
| `IssuePasswordResetRequest` | Injected: `VerificationRequestTokenHasher`, `VerificationRequestRepository`. Invalidates existing pending password reset, hashes token, computes expiry, delegates to `VerificationRequest.create()`. |
| `VerifyVerificationRequestToken` | Injected: `VerificationRequestTokenVerifier`. Checks expiry (calls `request.expire()`), verifies token. Calls `request.verify()` on success. Raises `VerificationRequestExpiredError` or `InvalidVerificationTokenError`. |

## Cross-Boundary Event Flow

Authentication is **always upstream**. It publishes events into the void — no knowledge of consumers.

**Events consumed by Audit (19 of 20 — `SessionRefreshed` is internal):** `AccountRegistered`, `LoginSucceeded`, `LoginFailed`, `EmailVerified`, `EmailChanged`, `PasswordChanged`, `AccountLocked`, `AccountUnlocked`, `AccountSuspended`, `AccountClosed`, `SessionStarted`, `SessionRevoked`, `DeviceRegistered`, `DeviceRevoked`, `VerificationRequestCreated`, `VerificationRequestVerified`, `VerificationRequestFailed`, `VerificationRequestInvalidated`, `VerificationRequestExpired`

**Events that trigger Notification (7):** `AccountRegistered` (welcome email), `VerificationRequestCreated[EMAIL_VERIFICATION]` (verification link), `VerificationRequestCreated[PASSWORD_RESET]` (reset link), `PasswordChanged` (confirmation), `AccountLocked` (alert), `AccountClosed` (confirmation), `DeviceRegistered` (new device alert)

---

## Rules

- Aggregates reference each other by ID only — never by direct object reference
- Cross-aggregate coordination uses domain events, not transactional coupling
- Secrets: passwords hashed, tokens hashed, fingerprints hashed
- `RawPassword`, `RawDeviceFingerprint`, `RawVerificationRequestToken` are transient — never persisted
- All repositories are async interfaces (ABC with abstract async methods)
- Domain interfaces (hashers, verifiers, checkers) are infrastructure contracts — domain depends on the interface, infrastructure provides the implementation

## References

- Design: `docs/domain/tactical-design.md` (Authentication Context section)
- Strategic: `docs/domain/strategic-design.md`
- Event flows: `docs/domain/event-storming.md`
- UML: `docs/diagrams/uml/authentication/account.puml`, `session.puml`, `device.puml`, `verification.puml`
- Glossary: `docs/domain/ubiquitous-language.md` (Authentication section)

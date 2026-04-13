# Event Storming

Event Storming artifacts for the pydentity identity management system, following Brandolini's Event Storming methodology. This document captures the Big Picture, Process Level, and Design Level storming results for all three bounded contexts (Authentication, Audit, Notification), organized by business process. All terms use the Ubiquitous Language defined in `ubiquitous-language.md`.

### Sticky Note Legend

| Color | Type | Naming Convention | Example |
|-------|------|-------------------|---------|
| Orange | Domain Event | Past tense | `AccountRegistered` |
| Blue | Command | Imperative | `RegisterAccount` |
| Yellow | Aggregate | Noun | `Account` |
| Lilac | Policy | "When X, then Y" | "When AccountRegistered, then IssueEmailVerificationRequest" |
| Green | Read Model | Descriptive | `AccountByEmail` |
| Pink | External System | System name | `CompromisedPasswordDatabase` |
| Red | Hot Spot | Free-form | "When does auto-unlock happen?" |

---

## Big Picture Event Storming

All 22 domain events placed on a chronological timeline, grouped by business phase. Events flow left-to-right from account creation through account closure.

### Timeline

```
past ──────────────────────────────────────────────────────────────────────────────── future

ONBOARDING
  AccountRegistered ──► VerificationRequestCreated ──► VerificationRequestVerified ──► EmailVerified

AUTHENTICATION & SESSION
  LoginSucceeded ──► DeviceRegistered ──► SessionStarted ──► SessionRefreshed ──► SessionEnded (LOGOUT)
  LoginFailed

CREDENTIAL MANAGEMENT
  PasswordChanged
  EmailChanged

VERIFICATION LIFECYCLE
  VerificationRequestCreated ──► VerificationRequestVerified
                              ──► VerificationRequestFailed
                              ──► VerificationRequestInvalidated
                              ──► VerificationRequestExpired

SECURITY ENFORCEMENT
  LoginFailed (threshold) ──► AccountLocked ──► DeviceRevoked (all) ──► SessionEnded (FORCED, all)
  AccountUnlocked

ACCOUNT LIFECYCLE
  AccountSuspended
  AccountClosed ──► DeviceRevoked (all) ──► SessionEnded (FORCED, all)

NOTIFICATION (cross-cutting)
  MessageDelivered
  MessageDeliveryFailed

AUDIT (cross-cutting)
  AuditEntry recorded for every event above
```

### Pivotal Events

Events that mark major state transitions in the business:

| Pivotal Event | Why It Is Pivotal |
|---------------|-------------------|
| AccountRegistered | Initiates the entire identity lifecycle; triggers onboarding chain (verification, welcome notification) |
| EmailVerified | Transitions Account from PENDING_VERIFICATION to ACTIVE; gate to full system usage |
| LoginFailed (threshold) | Boundary event that triggers automatic lockout — cascades to device revocation and session termination |
| AccountLocked | Triggers security cascade: all devices revoked, all sessions terminated, user notified |
| AccountClosed | Terminal state; triggers full cleanup of devices and sessions across the system |
| VerificationRequestCreated | Initiates time-limited verification flow; invalidates all prior pending requests of the same type |

---

## Process Level Event Storming

Each business process mapped as: Actor → Command → Aggregate → Domain Event → Policy → Next Command.

### Registration Flow

```
User (unauthenticated)
    │
    ▼
┌─────────────────┐     ┌─────────┐     ┌─────────────────────┐
│ RegisterAccount  │────►│ Account │────►│ AccountRegistered   │
│     (blue)       │     │(yellow) │     │      (orange)       │
└─────────────────┘     └─────────┘     └──────────┬──────────┘
                                                    │
        ┌───────────────────────────────────────────┤
        │                                           │
        ▼                                           ▼
┌──────────────────────────────┐    ┌──────────────────────────────────────┐
│ Policy: When AccountRegistered,│   │ Policy: When AccountRegistered,      │
│ then IssueEmailVerification   │   │ then SendWelcomeEmail                │
│ Request            (lilac)    │   │                        (lilac)       │
└──────────────┬───────────────┘    └──────────────────────────────────────┘
               │
               ▼
┌────────────────────────────────┐     ┌──────────────────────┐     ┌─────────────────────────────────┐
│ IssueEmailVerificationRequest  │────►│ VerificationRequest  │────►│ VerificationRequestCreated      │
│            (blue)              │     │       (yellow)       │     │            (orange)              │
└────────────────────────────────┘     └──────────────────────┘     └──────────────┬──────────────────┘
                                                                                   │
                                                                                   ▼
                                                                   ┌──────────────────────────────────────┐
                                                                   │ Policy: When VerificationRequest     │
                                                                   │ Created (EMAIL_VERIFICATION),        │
                                                                   │ then SendVerificationEmail   (lilac) │
                                                                   └──────────────────────────────────────┘
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | User (unauthenticated) | RegisterAccount | Account | AccountRegistered | When AccountRegistered, then IssueEmailVerificationRequest |
| 2 | Policy | IssueEmailVerificationRequest | VerificationRequest | VerificationRequestInvalidated (if any pending) + VerificationRequestCreated | When VerificationRequestCreated, then SendVerificationEmail |
| 3 | Policy | CreateDeliveryRequest (welcome) | DeliveryRequest | — | — |
| 4 | Policy | CreateDeliveryRequest (verification) | DeliveryRequest | — | — |

**Read Models:** AccountByEmail (email uniqueness check)
**External Systems:** CompromisedPasswordDatabase (breach check)

### Email Verification Flow

```
User (unauthenticated, via email link)
    │
    ▼
┌──────────────────────────┐     ┌──────────────────────┐     ┌────────────────────────────────┐
│ VerifyVerificationRequestToken│────►│ VerificationRequest  │────►│ VerificationRequestVerified    │
│         (blue)           │     │       (yellow)       │     │           (orange)             │
└──────────────────────────┘     └──────────────────────┘     └───────────────┬────────────────┘
                                                                              │
                                                                              ▼
                                                              ┌──────────────────────────────────────┐
                                                              │ Policy: When VerificationRequest     │
                                                              │ Verified (EMAIL_VERIFICATION),       │
                                                              │ then VerifyAccountEmail       (lilac) │
                                                              └──────────────────┬───────────────────┘
                                                                                 │
                                                                                 ▼
                                                              ┌────────────┐     ┌───────────────┐
                                                              │ VerifyEmail│────►│ EmailVerified │
                                                              │   (blue)   │     │   (orange)    │
                                                              └────────────┘     └───────────────┘
                                                                   │
                                                                Account (yellow)
```

**Failure path:**

```
User ──► VerifyVerificationRequestToken ──► VerificationRequest ──► VerificationRequestFailed
                                                                  (reason: INVALID_TOKEN | EXPIRED | ALREADY_VERIFIED)
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | User (unauthenticated) | VerifyVerificationRequestToken | VerificationRequest | VerificationRequestVerified | When Verified (EMAIL_VERIFICATION), then VerifyAccountEmail |
| 2 | Policy | VerifyEmail | Account | EmailVerified | — |
| Alt | User (unauthenticated) | VerifyVerificationRequestToken | VerificationRequest | VerificationRequestFailed | — |

### Authentication Flow

**Success path:**

```
User (unauthenticated)
    │
    ▼
┌──────────────┐     ┌─────────┐     ┌─────────────────┐
│ Authenticate │────►│ Account │────►│ LoginSucceeded  │
│    (blue)    │     │(yellow) │     │    (orange)     │
└──────────────┘     └─────────┘     └────────┬────────┘
                                               │
                                               ▼
                                  ┌────────────────┐     ┌────────┐     ┌──────────────────┐
                                  │ RegisterDevice │────►│ Device │────►│ DeviceRegistered │
                                  │     (blue)     │     │(yellow)│     │     (orange)     │
                                  └────────────────┘     └────────┘     └────────┬─────────┘
                                                                                 │
                                                         ┌───────────────────────┤
                                                         │                       │
                                                         ▼                       ▼
                                            ┌──────────────┐    ┌──────────────────────────────┐
                                            │ StartSession │    │ Policy: When DeviceRegistered│
                                            │    (blue)    │    │ then SendNewDeviceAlert      │
                                            └──────┬───────┘    │                     (lilac)  │
                                                   │            └──────────────────────────────┘
                                                   ▼
                                            ┌─────────┐     ┌────────────────┐
                                            │ Session │────►│ SessionStarted │
                                            │(yellow) │     │    (orange)    │
                                            └─────────┘     └────────────────┘
```

**Failure path:**

```
User (unauthenticated)
    │
    ▼
┌──────────────┐     ┌─────────┐     ┌──────────────┐
│ Authenticate │────►│ Account │────►│ LoginFailed  │
│    (blue)    │     │(yellow) │     │   (orange)   │
└──────────────┘     └─────────┘     └──────┬───────┘
                                             │
                                             ▼ (threshold exceeded)
                                 ┌──────────────────────────────────┐
                                 │ Policy: When LoginFailed         │
                                 │ (threshold), then LockAccount    │
                                 │                         (lilac)  │
                                 └──────────────┬───────────────────┘
                                                │
                                                ▼
                              ┌──────┐     ┌─────────┐     ┌───────────────┐
                              │ Lock │────►│ Account │────►│ AccountLocked │
                              │(blue)│     │(yellow) │     │   (orange)    │
                              └──────┘     └─────────┘     └───────┬───────┘
                                                                   │
                                                   ┌───────────────┤
                                                   │               │
                                                   ▼               ▼
                                   ┌─────────────────────┐  ┌──────────────────────────────┐
                                   │ Policy: RevokeAll   │  │ Policy: When AccountLocked   │
                                   │ Devices    (lilac)  │  │ (THRESHOLD), then Notify     │
                                   └──────────┬──────────┘  │ AccountLocked       (lilac)  │
                                              │             └──────────────────────────────┘
                                              ▼
                                   ┌───────────────┐     ┌────────┐     ┌───────────────┐
                                   │ RevokeDevices │────►│ Device │────►│ DeviceRevoked │
                                   │     (blue)    │     │(yellow)│     │   (orange)    │
                                   └───────────────┘     └────────┘     └───────┬───────┘
                                                                                │
                                                                                ▼
                                                                ┌──────────────────────────────┐
                                                                │ Policy: When DeviceRevoked,  │
                                                                │ then TerminateSessions       │
                                                                │                     (lilac)  │
                                                                └──────────────┬───────────────┘
                                                                               │
                                                                               ▼
                                                              ┌────────────────────┐     ┌─────────┐     ┌──────────────┐
                                                              │ TerminateSessions  │────►│ Session │────►│ SessionEnded │
                                                              │       (blue)       │     │(yellow) │     │   (orange)   │
                                                              └────────────────────┘     └─────────┘     └──────────────┘
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | User (unauthenticated) | Authenticate | Account | LoginSucceeded | — |
| 2 | System | RegisterDevice | Device | DeviceRegistered | When DeviceRegistered, then SendNewDeviceAlert |
| 3 | System | StartSession | Session | SessionStarted | — |
| Alt-1 | User (unauthenticated) | Authenticate | Account | LoginFailed | When LoginFailed (threshold), then LockAccount |
| Alt-2 | Policy | Lock (THRESHOLD) | Account | AccountLocked | When AccountLocked (THRESHOLD), then RevokeAllDevices + NotifyAccountLocked |
| Alt-3 | Policy | RevokeDevices (LOCKOUT) | Device(s) | DeviceRevoked | When DeviceRevoked, then TerminateSessions |
| Alt-4 | Policy | TerminateSessions (FORCED) | Session(s) | SessionEnded | — |

**Read Models:** AccountByEmail (account lookup)

### Password Reset Flow

```
User (unauthenticated)
    │
    ▼
┌──────────────────────────────┐     ┌──────────────────────┐     ┌─────────────────────────────────┐
│ IssuePasswordResetRequest    │────►│ VerificationRequest  │────►│ VerificationRequestCreated      │
│            (blue)            │     │       (yellow)       │     │           (orange)               │
└──────────────────────────────┘     └──────────────────────┘     └──────────────┬──────────────────┘
                                                                                 │
                                                                 ┌───────────────┤
                                                                 │               │
                                                                 ▼               ▼
                                                 ┌─────────────────────────┐  ┌──────────────────────────────┐
                                                 │ Policy: InvalidatePending│  │ Policy: When Verification    │
                                                 │ RequestsOfSameType      │  │ RequestCreated (PASSWORD_    │
                                                 │               (lilac)   │  │ RESET), then SendPassword    │
                                                 └─────────────────────────┘  │ ResetEmail          (lilac)  │
                                                                              └──────────────────────────────┘
```

Then the user receives the email, verifies the token, and changes the password:

```
User ──► VerifyVerificationRequestToken ──► VerificationRequest ──► VerificationRequestVerified
                                                                        │
                                                              (application presents password change form)
                                                                        │
                                                                        ▼
User ──► ChangePassword ──► Account ──► PasswordChanged ──► Policy: SendPasswordChangeConfirmation
              │
              ▼
   CompromisedPasswordDatabase (pink)
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | User (unauthenticated) | IssuePasswordResetRequest | VerificationRequest | VerificationRequestInvalidated (if any pending) + VerificationRequestCreated | When Created (PASSWORD_RESET), then SendPasswordResetEmail |
| 2 | User (unauthenticated) | VerifyVerificationRequestToken | VerificationRequest | VerificationRequestVerified | — |
| 3 | User | ChangePassword | Account | PasswordChanged | When PasswordChanged, then SendPasswordChangeConfirmation |

**External Systems:** CompromisedPasswordDatabase (breach check on new password)

### Password Change Flow

```
User (authenticated)
    │
    ▼
┌────────────────┐     ┌─────────┐     ┌─────────────────┐
│ ChangePassword │────►│ Account │────►│ PasswordChanged │
│     (blue)     │     │(yellow) │     │    (orange)     │
└────────────────┘     └─────────┘     └────────┬────────┘
        │                                       │
        ▼                                       ▼
CompromisedPassword             ┌───────────────────────────────────┐
Database      (pink)            │ Policy: When PasswordChanged,     │
                                │ then SendPasswordChangeConfirmation│
                                │                          (lilac)  │
                                └───────────────────────────────────┘
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | User (authenticated) | ChangePassword | Account | PasswordChanged | When PasswordChanged, then SendPasswordChangeConfirmation |

**External Systems:** CompromisedPasswordDatabase

### Email Change Flow

```
User (authenticated)
    │
    ▼
┌──────────────┐     ┌─────────┐     ┌──────────────┐
│ ChangeEmail  │────►│ Account │────►│ EmailChanged │
│    (blue)    │     │(yellow) │     │   (orange)   │
└──────────────┘     └─────────┘     └──────────────┘
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | User (authenticated) | ChangeEmail | Account | EmailChanged | — |

**Read Models:** AccountByEmail (duplicate check via PreventDuplicateEmail)

### Session Management Flow

**Refresh:**

```
User (authenticated) ──► RefreshSession (blue) ──► Session (yellow) ──► SessionRefreshed (orange)
```

**Logout:**

```
User (authenticated) ──► EndSession [LOGOUT] (blue) ──► Session (yellow) ──► SessionEnded (orange)
```

**Expiration:**

```
System/Scheduler ──► EndSession [EXPIRED] (blue) ──► Session (yellow) ──► SessionEnded (orange)
```

**Forced termination (by policy):**

```
Policy ──► TerminateSessions [FORCED | COMPROMISE] (blue) ──► Session(s) (yellow) ──► SessionEnded (orange)
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1a | User (authenticated) | RefreshSession | Session | SessionRefreshed | — |
| 1b | User (authenticated) | EndSession (LOGOUT) | Session | SessionEnded | — |
| 1c | System/Scheduler | EndSession (EXPIRED) | Session | SessionEnded | — |
| 1d | Policy | TerminateSessions (FORCED) | Session(s) | SessionEnded | — |

### Device Management Flow

**Registration (during login):**

```
System ──► RegisterDevice (blue) ──► Device (yellow) ──► DeviceRegistered (orange)
                │                                              │
                ▼                                              ▼
    ActiveDeviceCount              ┌──────────────────────────────────┐
    ByAccount (green)              │ Policy: When DeviceRegistered,   │
                                   │ then SendNewDeviceAlert  (lilac) │
                                   └──────────────────────────────────┘
```

**Manual revocation:**

```
User (authenticated) ──► RevokeDevice [MANUAL] (blue) ──► Device (yellow) ──► DeviceRevoked (orange)
                                                                                     │
                                                                                     ▼
                                                                     ┌──────────────────────────────┐
                                                                     │ Policy: When DeviceRevoked,  │
                                                                     │ then TerminateSessions       │
                                                                     │                     (lilac)  │
                                                                     └──────────────┬───────────────┘
                                                                                    │
                                                                                    ▼
                                                                     TerminateSessions ──► Session(s) ──► SessionEnded
```

**Admin revocation:**

```
Admin ──► RevokeDevice [ADMIN] (blue) ──► Device (yellow) ──► DeviceRevoked (orange) ──► Policy: TerminateSessions
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | System (login flow) | RegisterDevice | Device | DeviceRegistered | When DeviceRegistered, then SendNewDeviceAlert |
| 2a | User (authenticated) | RevokeDevice (MANUAL) | Device | DeviceRevoked | When DeviceRevoked, then TerminateSessions |
| 2b | Admin | RevokeDevice (ADMIN) | Device | DeviceRevoked | When DeviceRevoked, then TerminateSessions |
| 3 | Policy | TerminateSessions | Session(s) | SessionEnded | — |

**Read Models:** ActiveDeviceCountByAccount (device limit enforcement)

### Account Lifecycle Flow

**Lock (admin):**

```
Admin ──► Lock [ADMIN] (blue) ──► Account (yellow) ──► AccountLocked (orange) ──► Policy: RevokeAllDevices + NotifyAccountLocked
```

**Lock (threshold) — see Authentication Flow failure path.**

**Unlock:**

```
Admin ──► Unlock [ADMIN] (blue) ──► Account (yellow) ──► AccountUnlocked (orange)
System/Scheduler ──► Unlock [EXPIRY] (blue) ──► Account (yellow) ──► AccountUnlocked (orange)
```

**Suspend:**

```
Admin ──► Suspend (blue) ──► Account (yellow) ──► AccountSuspended (orange)
```

**Close:**

```
User/Admin ──► Close (blue) ──► Account (yellow) ──► AccountClosed (orange)
                                                            │
                                            ┌───────────────┤
                                            │               │
                                            ▼               ▼
                            ┌─────────────────────┐  ┌───────────────────────────────┐
                            │ Policy: RevokeAll   │  │ Policy: When AccountClosed,   │
                            │ Devices (CLOSURE)   │  │ then SendClosureConfirmation  │
                            │            (lilac)  │  │                      (lilac)  │
                            └──────────┬──────────┘  └───────────────────────────────┘
                                       │
                                       ▼
                            RevokeDevices ──► Device(s) ──► DeviceRevoked
                                                                  │
                                                                  ▼
                                                   Policy: TerminateSessions
                                                                  │
                                                                  ▼
                                                   TerminateSessions ──► Session(s) ──► SessionEnded
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1a | Admin | Lock (ADMIN) | Account | AccountLocked | RevokeAllDevices + NotifyAccountLocked |
| 1b | Admin / System | Unlock (ADMIN / EXPIRY) | Account | AccountUnlocked | — |
| 1c | Admin | Suspend | Account | AccountSuspended | — |
| 1d | User / Admin | Close | Account | AccountClosed | RevokeAllDevices (CLOSURE) + SendClosureConfirmation |
| 2 | Policy | RevokeDevices | Device(s) | DeviceRevoked | When DeviceRevoked, then TerminateSessions |
| 3 | Policy | TerminateSessions | Session(s) | SessionEnded | — |

### Verification Request Lifecycle

**Expiration:**

```
System/Scheduler ──► Expire (blue) ──► VerificationRequest (yellow) ──► VerificationRequestExpired (orange)
```

**Invalidation (automatic, internal to issue services when new request is created):**

Invalidation of pending requests is handled internally by `IssueEmailVerificationRequest` / `IssuePasswordResetRequest` — not a standalone command.

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | System/Scheduler | Expire | VerificationRequest | VerificationRequestExpired | — |

### Notification Delivery Flow

```
Policy trigger
    │
    ▼
┌───────────────────────┐     ┌─────────────────┐
│ CreateDeliveryRequest │────►│ DeliveryRequest  │ (PENDING)
│        (blue)         │     │    (yellow)      │
└───────────────────────┘     └────────┬─────────┘
                                       │
                                       ▼
                              Email/SMS Delivery
                              Service     (pink)
                                       │
                              ┌────────┴────────┐
                              │                 │
                         success            failure
                              │                 │
                              ▼                 ▼
                       ┌───────────┐     ┌─────────────────────┐
                       │ MarkSent  │     │ RecordFailedAttempt │
                       │  (blue)   │     │       (blue)        │
                       └─────┬─────┘     └──────────┬──────────┘
                             │                      │
                             ▼               (retry or give up)
                    ┌──────────────────┐            │
                    │ MessageDelivered │            ▼
                    │    (orange)      │     ┌────────────┐
                    └────────┬─────────┘     │ MarkFailed │
                             │               │   (blue)   │
                  (if SENSITIVE)              └──────┬─────┘
                             │                      │
                             ▼                      ▼
                    ┌──────────────┐     ┌────────────────────────┐
                    │ PurgeContent │     │ MessageDeliveryFailed  │
                    │    (blue)    │     │       (orange)         │
                    └──────────────┘     └────────────────────────┘
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | Policy (event handler) | CreateDeliveryRequest | DeliveryRequest | — | — |
| 2a | System (infrastructure) | MarkSent | DeliveryRequest | MessageDelivered | — |
| 2b | System (infrastructure) | RecordFailedAttempt | DeliveryRequest | — | — |
| 3a | System (post-delivery) | PurgeContent | DeliveryRequest | — | — |
| 3b | System (infrastructure) | MarkFailed | DeliveryRequest | MessageDeliveryFailed | — |

**External Systems:** EmailDeliveryService, SMSDeliveryService

### Audit Recording Flow

```
Any Authentication/Notification Domain Event ──► RecordAuditEntry (blue) ──► AuditEntry (yellow, immutable)
```

| Step | Actor | Command | Aggregate | Domain Event | Policy |
|------|-------|---------|-----------|-------------|--------|
| 1 | System (event handler) | RecordAuditEntry | AuditEntry | — | — |

Simple downstream consumer. Append-only, no policies, no cascading.

---

## Design Level Event Storming

Detailed templates for every command, event, policy, and hot spot.

### Command Details

#### Register Account

| Field | Value |
|-------|-------|
| Command | RegisterAccount |
| Actor | User (unauthenticated) |
| Target Aggregate | Account |
| Parameters | email: Email, password: RawPassword |
| Preconditions | Email not already registered (PreventDuplicateEmail). Password not compromised (CompromisedPasswordChecker). Password satisfies PasswordPolicy (min_length, max_length). |

#### Authenticate

| Field | Value |
|-------|-------|
| Command | Authenticate |
| Actor | User (unauthenticated) |
| Target Aggregate | Account |
| Parameters | password: RawPassword, verifier: PasswordVerifier, lockout_policy: LockoutPolicy |
| Preconditions | Account exists. Account status is not CLOSED or SUSPENDED. |

#### Verify Email

| Field | Value |
|-------|-------|
| Command | VerifyEmail |
| Actor | Policy (triggered by VerificationRequestVerified) |
| Target Aggregate | Account |
| Parameters | — |
| Preconditions | Account status is PENDING_VERIFICATION. |

#### Change Password

| Field | Value |
|-------|-------|
| Command | ChangePassword |
| Actor | User (authenticated) |
| Target Aggregate | Account |
| Parameters | current_password: RawPassword, new_password: RawPassword |
| Preconditions | Account status is ACTIVE. Current password is correct (PasswordVerifier). New password not compromised (CompromisedPasswordChecker). New password satisfies PasswordPolicy. New password not in password history (max_history). |

#### Change Email

| Field | Value |
|-------|-------|
| Command | ChangeEmail |
| Actor | User (authenticated) |
| Target Aggregate | Account |
| Parameters | new_email: Email |
| Preconditions | Account status is ACTIVE. New email not already registered (PreventDuplicateEmail). |

#### Lock Account

| Field | Value |
|-------|-------|
| Command | Lock |
| Actor | Policy (THRESHOLD) or Admin (ADMIN) |
| Target Aggregate | Account |
| Parameters | reason: LockReason (THRESHOLD or ADMIN) |
| Preconditions | Account status is ACTIVE. |

#### Unlock Account

| Field | Value |
|-------|-------|
| Command | Unlock |
| Actor | Admin (ADMIN) or System/Scheduler (EXPIRY) |
| Target Aggregate | Account |
| Parameters | reason: UnlockReason (EXPIRY or ADMIN) |
| Preconditions | Account status is LOCKED. |

#### Suspend Account

| Field | Value |
|-------|-------|
| Command | Suspend |
| Actor | Admin |
| Target Aggregate | Account |
| Parameters | — |
| Preconditions | Account status is ACTIVE. |

#### Close Account

| Field | Value |
|-------|-------|
| Command | Close |
| Actor | User (authenticated) or Admin |
| Target Aggregate | Account |
| Parameters | — |
| Preconditions | Account status is ACTIVE. |

#### Start Session

| Field | Value |
|-------|-------|
| Command | StartSession |
| Actor | System (after successful login) |
| Target Aggregate | Session |
| Parameters | account_id: AccountId, device_id: DeviceId, policy: SessionPolicy |
| Preconditions | Account authenticated. Device registered and ACTIVE. |

#### End Session

| Field | Value |
|-------|-------|
| Command | EndSession |
| Actor | User (LOGOUT), System/Scheduler (EXPIRED), Policy (FORCED, COMPROMISE) |
| Target Aggregate | Session |
| Parameters | reason: SessionEndReason (LOGOUT, EXPIRED, FORCED, COMPROMISE) |
| Preconditions | Session status is ACTIVE. |

#### Refresh Session

| Field | Value |
|-------|-------|
| Command | RefreshSession |
| Actor | User (authenticated) |
| Target Aggregate | Session |
| Parameters | policy: SessionPolicy |
| Preconditions | Session status is ACTIVE. |

#### Register Device

| Field | Value |
|-------|-------|
| Command | RegisterDevice |
| Actor | System (during login flow) |
| Target Aggregate | Device |
| Parameters | account_id: AccountId, fingerprint: RawDeviceFingerprint, policy: DevicePolicy |
| Preconditions | Active device count for account < DevicePolicy.max_devices_per_account. |

#### Revoke Device

| Field | Value |
|-------|-------|
| Command | RevokeDevice |
| Actor | User (MANUAL), Admin (ADMIN), Policy (LOCKOUT, CLOSURE) |
| Target Aggregate | Device |
| Parameters | reason: DeviceRevocationReason (MANUAL, ADMIN, LOCKOUT, CLOSURE) |
| Preconditions | Device status is ACTIVE. |

#### Issue Email Verification Request

| Field | Value |
|-------|-------|
| Command | IssueEmailVerificationRequest |
| Actor | Policy (triggered by AccountRegistered) |
| Target Aggregate | VerificationRequest |
| Parameters | verification_request_id: VerificationRequestId, account_id: AccountId, raw_token: RawVerificationRequestToken, policy: VerificationPolicy, current_time: datetime |
| Preconditions | Account exists. |
| Side Effects | Invalidates pending email verification requests for the same account (internal to service). |

#### Issue Password Reset Request

| Field | Value |
|-------|-------|
| Command | IssuePasswordResetRequest |
| Actor | User (unauthenticated) |
| Target Aggregate | VerificationRequest |
| Parameters | verification_request_id: VerificationRequestId, account_id: AccountId, raw_token: RawVerificationRequestToken, policy: VerificationPolicy, current_time: datetime |
| Preconditions | Account exists. |
| Side Effects | Invalidates pending password reset requests for the same account (internal to service). |

#### Verify Verification Request Token

| Field | Value |
|-------|-------|
| Command | VerifyVerificationRequestToken |
| Actor | User (unauthenticated, via email link) |
| Target Aggregate | VerificationRequest |
| Parameters | request: VerificationRequest, token: RawVerificationRequestToken, current_time: datetime |
| Preconditions | Request status is PENDING. Request is not expired (current_time < expiry). Token is valid (verifier confirms match). |

#### Expire Verification Request

| Field | Value |
|-------|-------|
| Command | Expire |
| Actor | System/Scheduler |
| Target Aggregate | VerificationRequest |
| Parameters | — |
| Preconditions | Request status is PENDING. Current time is past expiry. |

#### Record Audit Entry

| Field | Value |
|-------|-------|
| Command | RecordAuditEntry |
| Actor | System (event handler) |
| Target Aggregate | AuditEntry |
| Parameters | id: AuditEntryId, event_name: EventName, account_id: AccountId, payload: EventPayload |
| Preconditions | None (always succeeds). |

#### Create Delivery Request

| Field | Value |
|-------|-------|
| Command | CreateDeliveryRequest |
| Actor | Policy (event handler) |
| Target Aggregate | DeliveryRequest |
| Parameters | id: DeliveryRequestId, account_id: AccountId, recipient: Recipient, channel: Channel, content: MessageContent, sensitivity: ContentSensitivity |
| Preconditions | None. |

#### Mark Sent

| Field | Value |
|-------|-------|
| Command | MarkSent |
| Actor | System (infrastructure, after successful delivery) |
| Target Aggregate | DeliveryRequest |
| Parameters | — |
| Preconditions | Status is PENDING. |

#### Record Failed Attempt

| Field | Value |
|-------|-------|
| Command | RecordFailedAttempt |
| Actor | System (infrastructure, after failed delivery) |
| Target Aggregate | DeliveryRequest |
| Parameters | — |
| Preconditions | Status is PENDING. |

#### Mark Failed

| Field | Value |
|-------|-------|
| Command | MarkFailed |
| Actor | System (infrastructure, after exhausting retries) |
| Target Aggregate | DeliveryRequest |
| Parameters | — |
| Preconditions | Status is PENDING. |

#### Purge Content

| Field | Value |
|-------|-------|
| Command | PurgeContent |
| Actor | System (post-delivery cleanup) |
| Target Aggregate | DeliveryRequest |
| Parameters | — |
| Preconditions | Status is SENT. Sensitivity is SENSITIVE. |

### Domain Event Details

#### Account Registered

| Field | Value |
|-------|-------|
| Event | AccountRegistered |
| Produced By | Account |
| Payload | account_id: AccountId, email: Email |
| Triggers | Policy: When AccountRegistered, then IssueEmailVerificationRequest. Policy: When AccountRegistered, then SendWelcomeEmail. |
| Consumed By | Audit (record entry), Notification (welcome email, verification email) |

#### Login Succeeded

| Field | Value |
|-------|-------|
| Event | LoginSucceeded |
| Produced By | Account |
| Payload | account_id: AccountId |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Login Failed

| Field | Value |
|-------|-------|
| Event | LoginFailed |
| Produced By | Account |
| Payload | account_id: AccountId, failed_attempt_count: FailedAttemptCount |
| Triggers | Policy: When LoginFailed (threshold exceeded), then LockAccount (THRESHOLD) |
| Consumed By | Audit (record entry) |

#### Email Verified

| Field | Value |
|-------|-------|
| Event | EmailVerified |
| Produced By | Account |
| Payload | account_id: AccountId |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Email Changed

| Field | Value |
|-------|-------|
| Event | EmailChanged |
| Produced By | Account |
| Payload | account_id: AccountId, old_email: Email, new_email: Email |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Password Changed

| Field | Value |
|-------|-------|
| Event | PasswordChanged |
| Produced By | Account |
| Payload | account_id: AccountId |
| Triggers | Policy: When PasswordChanged, then SendPasswordChangeConfirmation |
| Consumed By | Audit (record entry), Notification (confirmation email) |

#### Account Locked

| Field | Value |
|-------|-------|
| Event | AccountLocked |
| Produced By | Account |
| Payload | account_id: AccountId, reason: LockReason |
| Triggers | Policy: When AccountLocked, then RevokeAllDevices. Policy: When AccountLocked (THRESHOLD), then NotifyAccountLocked. |
| Consumed By | Audit (record entry), Notification (locked alert) |

#### Account Unlocked

| Field | Value |
|-------|-------|
| Event | AccountUnlocked |
| Produced By | Account |
| Payload | account_id: AccountId, reason: UnlockReason |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Account Suspended

| Field | Value |
|-------|-------|
| Event | AccountSuspended |
| Produced By | Account |
| Payload | account_id: AccountId |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Account Closed

| Field | Value |
|-------|-------|
| Event | AccountClosed |
| Produced By | Account |
| Payload | account_id: AccountId |
| Triggers | Policy: When AccountClosed, then RevokeAllDevices (CLOSURE). Policy: When AccountClosed, then SendClosureConfirmation. |
| Consumed By | Audit (record entry), Notification (closure confirmation) |

#### Session Started

| Field | Value |
|-------|-------|
| Event | SessionStarted |
| Produced By | Session |
| Payload | session_id: SessionId, account_id: AccountId, device_id: DeviceId |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Session Ended

| Field | Value |
|-------|-------|
| Event | SessionEnded |
| Produced By | Session |
| Payload | session_id: SessionId, account_id: AccountId, device_id: DeviceId, reason: SessionEndReason |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Session Refreshed

| Field | Value |
|-------|-------|
| Event | SessionRefreshed |
| Produced By | Session |
| Payload | session_id: SessionId, account_id: AccountId, device_id: DeviceId |
| Triggers | None |
| Consumed By | None (internal only) |

#### Device Registered

| Field | Value |
|-------|-------|
| Event | DeviceRegistered |
| Produced By | Device |
| Payload | device_id: DeviceId, account_id: AccountId |
| Triggers | Policy: When DeviceRegistered, then SendNewDeviceAlert |
| Consumed By | Audit (record entry), Notification (new device alert) |

#### Device Revoked

| Field | Value |
|-------|-------|
| Event | DeviceRevoked |
| Produced By | Device |
| Payload | device_id: DeviceId, account_id: AccountId, reason: DeviceRevocationReason |
| Triggers | Policy: When DeviceRevoked, then TerminateSessions |
| Consumed By | Audit (record entry) |

#### Verification Request Created

| Field | Value |
|-------|-------|
| Event | VerificationRequestCreated |
| Produced By | VerificationRequest |
| Payload | verification_request_id: VerificationRequestId, account_id: AccountId, type: VerificationRequestType |
| Triggers | Policy: When Created (EMAIL_VERIFICATION), then SendVerificationEmail. Policy: When Created (PASSWORD_RESET), then SendPasswordResetEmail. Policy: When Created, then InvalidatePendingRequestsOfSameType. |
| Consumed By | Audit (record entry), Notification (verification/reset email) |

#### Verification Request Verified

| Field | Value |
|-------|-------|
| Event | VerificationRequestVerified |
| Produced By | VerificationRequest |
| Payload | verification_request_id: VerificationRequestId, account_id: AccountId |
| Triggers | Policy: When Verified (EMAIL_VERIFICATION), then VerifyAccountEmail |
| Consumed By | Audit (record entry) |

#### Verification Request Failed

| Field | Value |
|-------|-------|
| Event | VerificationRequestFailed |
| Produced By | VerificationRequest |
| Payload | verification_request_id: VerificationRequestId, account_id: AccountId, reason: VerificationFailureReason |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Verification Request Invalidated

| Field | Value |
|-------|-------|
| Event | VerificationRequestInvalidated |
| Produced By | VerificationRequest |
| Payload | verification_request_id: VerificationRequestId, account_id: AccountId |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Verification Request Expired

| Field | Value |
|-------|-------|
| Event | VerificationRequestExpired |
| Produced By | VerificationRequest |
| Payload | verification_request_id: VerificationRequestId, account_id: AccountId |
| Triggers | None |
| Consumed By | Audit (record entry) |

#### Message Delivered

| Field | Value |
|-------|-------|
| Event | MessageDelivered |
| Produced By | DeliveryRequest |
| Payload | delivery_request_id: DeliveryRequestId, account_id: AccountId |
| Triggers | None |
| Consumed By | None |

#### Message Delivery Failed

| Field | Value |
|-------|-------|
| Event | MessageDeliveryFailed |
| Produced By | DeliveryRequest |
| Payload | delivery_request_id: DeliveryRequestId, account_id: AccountId |
| Triggers | None |
| Consumed By | None |

### Policy Details

#### When Account Registered, then Create Email Verification Request

| Field | Value |
|-------|-------|
| Policy | When AccountRegistered, then IssueEmailVerificationRequest |
| Trigger Event | AccountRegistered |
| Resulting Command | IssueEmailVerificationRequest |
| Conditions | Unconditional — always triggered after account registration |

#### When Account Registered, then Send Welcome Email

| Field | Value |
|-------|-------|
| Policy | When AccountRegistered, then SendWelcomeEmail |
| Trigger Event | AccountRegistered |
| Resulting Command | CreateDeliveryRequest (channel: EMAIL, sensitivity: STANDARD) |
| Conditions | Unconditional |

#### When Verification Request Created (EMAIL_VERIFICATION), then Send Verification Email

| Field | Value |
|-------|-------|
| Policy | When VerificationRequestCreated (EMAIL_VERIFICATION), then SendVerificationEmail |
| Trigger Event | VerificationRequestCreated |
| Resulting Command | CreateDeliveryRequest (channel: EMAIL, sensitivity: SENSITIVE) |
| Conditions | type = EMAIL_VERIFICATION |

#### When Verification Request Created (PASSWORD_RESET), then Send Password Reset Email

| Field | Value |
|-------|-------|
| Policy | When VerificationRequestCreated (PASSWORD_RESET), then SendPasswordResetEmail |
| Trigger Event | VerificationRequestCreated |
| Resulting Command | CreateDeliveryRequest (channel: EMAIL, sensitivity: SENSITIVE) |
| Conditions | type = PASSWORD_RESET |

#### When Verification Request Created, then Invalidate Pending Requests of Same Type

| Field | Value |
|-------|-------|
| Policy | When VerificationRequestCreated, then InvalidatePendingRequestsOfSameType |
| Trigger Event | VerificationRequestCreated |
| Resulting Command | (handled internally by IssueEmailVerificationRequest / IssuePasswordResetRequest) |
| Conditions | Unconditional — runs for every new verification request |

#### When Login Failed (threshold exceeded), then Lock Account

| Field | Value |
|-------|-------|
| Policy | When LoginFailed (threshold exceeded), then LockAccount |
| Trigger Event | LoginFailed |
| Resulting Command | Lock (reason: THRESHOLD) |
| Conditions | failed_attempt_count >= LockoutPolicy.max_failed_attempts |

#### When Account Locked (THRESHOLD), then Notify Account Locked

| Field | Value |
|-------|-------|
| Policy | When AccountLocked (THRESHOLD), then NotifyAccountLocked |
| Trigger Event | AccountLocked |
| Resulting Command | CreateDeliveryRequest (channel: EMAIL, sensitivity: STANDARD) |
| Conditions | reason = THRESHOLD |

#### When Account Closed, then Revoke All Devices and Send Closure Confirmation

| Field | Value |
|-------|-------|
| Policy | When AccountClosed, then RevokeAllDevices + SendClosureConfirmation |
| Trigger Event | AccountClosed |
| Resulting Command | RevokeDevices (reason: CLOSURE) + CreateDeliveryRequest (channel: EMAIL, sensitivity: STANDARD) |
| Conditions | Unconditional |

#### When Device Revoked, then Terminate Sessions for Device

| Field | Value |
|-------|-------|
| Policy | When DeviceRevoked, then TerminateSessionsForDevice |
| Trigger Event | DeviceRevoked |
| Resulting Command | TerminateSessions (device_id, reason: FORCED) |
| Conditions | Unconditional — every device revocation terminates its active sessions |

#### When Verification Request Verified (EMAIL_VERIFICATION), then Verify Account Email

| Field | Value |
|-------|-------|
| Policy | When VerificationRequestVerified (EMAIL_VERIFICATION), then VerifyAccountEmail |
| Trigger Event | VerificationRequestVerified |
| Resulting Command | VerifyEmail on Account |
| Conditions | request type = EMAIL_VERIFICATION |

#### When Password Changed, then Send Password Change Confirmation

| Field | Value |
|-------|-------|
| Policy | When PasswordChanged, then SendPasswordChangeConfirmation |
| Trigger Event | PasswordChanged |
| Resulting Command | CreateDeliveryRequest (channel: EMAIL, sensitivity: STANDARD) |
| Conditions | Unconditional |

#### When Device Registered, then Send New Device Alert

| Field | Value |
|-------|-------|
| Policy | When DeviceRegistered, then SendNewDeviceAlert |
| Trigger Event | DeviceRegistered |
| Resulting Command | CreateDeliveryRequest (channel: EMAIL, sensitivity: STANDARD) |
| Conditions | Unconditional |

### Hot Spots

#### HS-01: Lockout Auto-Unlock Timing

| Field | Value |
|-------|-------|
| Description | LockoutPolicy has lockout_duration_seconds, but no explicit command or scheduler job for auto-unlock is modeled. Who triggers Unlock(EXPIRY)? |
| Category | Missing Requirement |
| Discovered During | Authentication Flow (failure path) |
| Resolution | A scheduled job or lazy check on next login attempt should transition LOCKED accounts past their lockout duration. Modeled as System/Scheduler actor calling Unlock(EXPIRY). |
| Owner | Authentication team |

#### HS-02: Device Registration During Login vs. Explicit

| Field | Value |
|-------|-------|
| Description | The login flow implies device registration happens automatically. Is device registration always part of login, or can it be a separate explicit action? |
| Category | Business Rule Ambiguity |
| Discovered During | Authentication Flow (success path) |
| Resolution | Device registration is part of the login flow when the device fingerprint is unrecognized. The application layer checks for existing device by fingerprint (DeviceFingerprintVerifier) before calling RegisterDevice. |
| Owner | Authentication team |

#### HS-03: Password Reset Post-Verification Flow

| Field | Value |
|-------|-------|
| Description | VerificationRequestVerified (PASSWORD_RESET) does not have a policy that automatically changes the password. The user must submit a new password separately. How is the verified state communicated? |
| Category | Business Rule Ambiguity |
| Discovered During | Password Reset Flow |
| Resolution | Application-layer concern. The application layer tracks the verified request and allows a one-time password change without requiring the current password. This is not a domain policy — it is orchestration. |
| Owner | Authentication team |

#### HS-04: Notification Delivery Retry Policy

| Field | Value |
|-------|-------|
| Description | DeliveryRequest has RecordFailedAttempt and MarkFailed, but the retry policy (max retries, backoff strategy) is not modeled in the domain. |
| Category | Technical Concern |
| Discovered During | Notification Delivery Flow |
| Resolution | Retry policy is an infrastructure concern. The application/infrastructure layer decides when to retry and when to call MarkFailed. The domain only tracks AttemptCount monotonically. |
| Owner | Notification team |

#### HS-05: Content Purge Timing for Sensitive Deliveries

| Field | Value |
|-------|-------|
| Description | When exactly is PurgeContent called? Immediately after MarkSent? Asynchronously via a scheduled job? |
| Category | Technical Concern |
| Discovered During | Notification Delivery Flow |
| Resolution | PurgeContent should be called immediately after MarkSent for SENSITIVE deliveries. A scheduled cleanup job can also sweep using DeliveryRequestRepository.find_sensitive_requiring_purge() as a safety net. |
| Owner | Notification team |

#### HS-06: Account Closure Eventual Consistency Window

| Field | Value |
|-------|-------|
| Description | AccountClosed triggers RevokeAllDevices, which triggers TerminateAllSessions. During the eventual consistency window, sessions on revoked devices could still be active. |
| Category | Technical Concern |
| Discovered During | Account Lifecycle Flow |
| Resolution | Acceptable eventual consistency. Session validation at the application layer should also check account status as a defense-in-depth measure, rejecting requests for closed accounts regardless of session state. |
| Owner | Authentication team |

#### HS-07: Email Change — Should It Trigger Re-Verification?

| Field | Value |
|-------|-------|
| Description | EmailChanged is audited but does not trigger a new email verification flow. Should the Account return to PENDING_VERIFICATION after email change? |
| Category | Business Rule Ambiguity |
| Discovered During | Email Change Flow |
| Resolution | Current design does not re-verify on email change. This is a deliberate simplification. If re-verification is needed in the future, add a policy "When EmailChanged, then IssueEmailVerificationRequest" and revert account status. |
| Owner | Product |

#### HS-08: SMS Channel — When Is It Used?

| Field | Value |
|-------|-------|
| Description | The Channel enum includes SMS, but no current policy or flow explicitly triggers SMS delivery. All notification policies use EMAIL. |
| Category | Missing Requirement |
| Discovered During | Notification Delivery Flow |
| Resolution | SMS is modeled for future extensibility (2FA, phone-based verification). No current business process requires SMS. Policies will be defined when SMS use cases are introduced. |
| Owner | Product |

---

## Artifact Extraction Catalog

### Domain Events

| # | Event | Bounded Context | Produced By |
|---|-------|----------------|-------------|
| 1 | AccountRegistered | Authentication | Account |
| 2 | LoginSucceeded | Authentication | Account |
| 3 | LoginFailed | Authentication | Account |
| 4 | EmailVerified | Authentication | Account |
| 5 | EmailChanged | Authentication | Account |
| 6 | PasswordChanged | Authentication | Account |
| 7 | AccountLocked | Authentication | Account |
| 8 | AccountUnlocked | Authentication | Account |
| 9 | AccountSuspended | Authentication | Account |
| 10 | AccountClosed | Authentication | Account |
| 11 | SessionStarted | Authentication | Session |
| 12 | SessionEnded | Authentication | Session |
| 13 | SessionRefreshed | Authentication | Session |
| 14 | DeviceRegistered | Authentication | Device |
| 15 | DeviceRevoked | Authentication | Device |
| 16 | VerificationRequestCreated | Authentication | VerificationRequest |
| 17 | VerificationRequestVerified | Authentication | VerificationRequest |
| 18 | VerificationRequestFailed | Authentication | VerificationRequest |
| 19 | VerificationRequestInvalidated | Authentication | VerificationRequest |
| 20 | VerificationRequestExpired | Authentication | VerificationRequest |
| 21 | MessageDelivered | Notification | DeliveryRequest |
| 22 | MessageDeliveryFailed | Notification | DeliveryRequest |

### Commands

| # | Command | Bounded Context | Target Aggregate | Actor |
|---|---------|----------------|-----------------|-------|
| 1 | RegisterAccount | Authentication | Account | User (unauthenticated) |
| 2 | Authenticate | Authentication | Account | User (unauthenticated) |
| 3 | VerifyEmail | Authentication | Account | Policy |
| 4 | ChangePassword | Authentication | Account | User (authenticated) |
| 5 | ChangeEmail | Authentication | Account | User (authenticated) |
| 6 | Lock | Authentication | Account | Policy / Admin |
| 7 | Unlock | Authentication | Account | Admin / System |
| 8 | Suspend | Authentication | Account | Admin |
| 9 | Close | Authentication | Account | User / Admin |
| 10 | StartSession | Authentication | Session | System |
| 11 | EndSession | Authentication | Session | User / System / Policy |
| 12 | RefreshSession | Authentication | Session | User (authenticated) |
| 13 | RegisterDevice | Authentication | Device | System |
| 14 | RevokeDevice | Authentication | Device | User / Admin / Policy |
| 15 | IssueEmailVerificationRequest | Authentication | VerificationRequest | Policy |
| 16 | IssuePasswordResetRequest | Authentication | VerificationRequest | User (unauthenticated) |
| 17 | VerifyVerificationRequestToken | Authentication | VerificationRequest | User (unauthenticated) |
| 19 | ExpireVerificationRequest | Authentication | VerificationRequest | System/Scheduler |
| 20 | RecordAuditEntry | Audit | AuditEntry | System (event handler) |
| 21 | CreateDeliveryRequest | Notification | DeliveryRequest | Policy (event handler) |
| 22 | MarkSent | Notification | DeliveryRequest | System (infrastructure) |
| 23 | RecordFailedAttempt | Notification | DeliveryRequest | System (infrastructure) |
| 24 | MarkFailed | Notification | DeliveryRequest | System (infrastructure) |
| 25 | PurgeContent | Notification | DeliveryRequest | System (post-delivery) |

### Aggregates

| # | Aggregate | Bounded Context | Key Invariants |
|---|-----------|----------------|----------------|
| 1 | Account | Authentication | Password history prevents reuse. Failed attempts consistent with lock status. Status transitions follow state machine. Email unique across accounts. Password checked against breach database. |
| 2 | Session | Authentication | End/refresh only when ACTIVE. Expiration can only be extended on refresh. |
| 3 | Device | Authentication | Revoke only when ACTIVE. Active device count per account must not exceed DevicePolicy.max_devices_per_account. |
| 4 | VerificationRequest | Authentication | Verify only when PENDING and not expired. Token must match hash. Status transitions follow state machine. Pending requests invalidated when new request of same type created. |
| 5 | AuditEntry | Audit | Immutable after creation (append-only, no update or delete). |
| 6 | DeliveryRequest | Notification | Status transitions: PENDING → SENT or PENDING → FAILED. Content purged only for SENSITIVE after SENT. Attempt count monotonically increasing. |

### Policies

| # | Policy | Trigger Event | Resulting Command | Conditions |
|---|--------|--------------|-------------------|------------|
| 1 | IssueEmailVerificationRequest | AccountRegistered | IssueEmailVerificationRequest | Unconditional |
| 2 | SendWelcomeEmail | AccountRegistered | CreateDeliveryRequest (EMAIL, STANDARD) | Unconditional |
| 3 | SendVerificationEmail | VerificationRequestCreated | CreateDeliveryRequest (EMAIL, SENSITIVE) | type = EMAIL_VERIFICATION |
| 4 | SendPasswordResetEmail | VerificationRequestCreated | CreateDeliveryRequest (EMAIL, SENSITIVE) | type = PASSWORD_RESET |
| 5 | InvalidatePendingRequestsOfSameType | VerificationRequestCreated | (handled internally by issue services) | Unconditional |
| 6 | LockAccount | LoginFailed | Lock (THRESHOLD) | failed_attempt_count >= max_failed_attempts |
| 7 | NotifyAccountLocked | AccountLocked | CreateDeliveryRequest (EMAIL, STANDARD) | reason = THRESHOLD |
| 8 | RevokeAllDevicesAndNotifyClosure | AccountClosed | RevokeDevices (CLOSURE) + CreateDeliveryRequest (EMAIL, STANDARD) | Unconditional |
| 9 | TerminateSessionsForDevice | DeviceRevoked | TerminateSessions (FORCED) | Unconditional |
| 10 | VerifyAccountEmail | VerificationRequestVerified | VerifyEmail | type = EMAIL_VERIFICATION |
| 11 | SendPasswordChangeConfirmation | PasswordChanged | CreateDeliveryRequest (EMAIL, STANDARD) | Unconditional |
| 12 | SendNewDeviceAlert | DeviceRegistered | CreateDeliveryRequest (EMAIL, STANDARD) | Unconditional |

### Read Models

| # | Read Model | Used In | Purpose |
|---|-----------|---------|---------|
| 1 | AccountByEmail | Registration, Authentication | Find account by email for login; check email uniqueness via PreventDuplicateEmail |
| 2 | ActiveDeviceCountByAccount | Device Registration | Enforce DevicePolicy.max_devices_per_account limit |
| 3 | PendingVerificationRequestsByAccountAndType | Verification Request Creation | Find pending requests to invalidate when new request is created |
| 4 | ActiveSessionsByDevice | Device Revocation | Find active sessions to terminate when device is revoked |
| 5 | PendingDeliveryRequests | Notification Delivery | Process pending delivery requests for sending |
| 6 | SensitiveDeliveriesRequiringPurge | Content Purge | Find delivered sensitive messages needing content purge |

### External Systems

| # | External System | Used In | Integration |
|---|----------------|---------|-------------|
| 1 | CompromisedPasswordDatabase | Registration, Password Change | Domain Interface: CompromisedPasswordChecker — checks passwords against known breaches (NIST 800-63B) |
| 2 | EmailDeliveryService | Notification Delivery | Infrastructure adapter for DeliveryRequest (channel: EMAIL) |
| 3 | SMSDeliveryService | Notification Delivery (future) | Infrastructure adapter for DeliveryRequest (channel: SMS) |

### Hot Spots

| # | Hot Spot | Category | Status | Owner |
|---|---------|----------|--------|-------|
| HS-01 | Lockout auto-unlock timing | Missing Requirement | Resolved: System/Scheduler actor | Authentication team |
| HS-02 | Device registration during login vs. explicit | Business Rule Ambiguity | Resolved: Part of login flow | Authentication team |
| HS-03 | Password reset post-verification flow | Business Rule Ambiguity | Resolved: Application-layer concern | Authentication team |
| HS-04 | Notification delivery retry policy | Technical Concern | Resolved: Infrastructure concern | Notification team |
| HS-05 | Content purge timing for sensitive deliveries | Technical Concern | Resolved: Immediate + scheduled | Notification team |
| HS-06 | Account closure eventual consistency window | Technical Concern | Resolved: Defense-in-depth | Authentication team |
| HS-07 | Email change re-verification | Business Rule Ambiguity | Resolved: Not required (deliberate) | Product |
| HS-08 | SMS channel usage | Missing Requirement | Resolved: Future extensibility | Product |

### Bounded Context Candidates

| # | Bounded Context | Aggregates | Rationale |
|---|----------------|-----------|-----------|
| 1 | Authentication (Core) | Account, Session, Device, VerificationRequest | Tightly coupled via AccountId. Shared authentication workflows and security invariants. Cohesive vocabulary (credentials, sessions, devices, verification). |
| 2 | Audit (Supporting) | AuditEntry | Different data model (append-only, generic payload). No shared invariants with Authentication. Different vocabulary (entries, event names, payloads). |
| 3 | Notification (Supporting) | DeliveryRequest | Independent delivery lifecycle. Different vocabulary (recipients, channels, attempts). No shared invariants with Authentication. |

These BC candidates confirm the boundaries established in `strategic-design.md`. No new BC candidates emerged from Event Storming.

---

## Gate 2 Checklist

| # | Check | Status | Evidence |
|---|-------|:------:|----------|
| 1 | Big Picture complete — full business process mapped end-to-end with Domain Events | YES | Timeline covers all 22 events from registration through account closure |
| 2 | Process Level complete — Commands, Aggregates, Policies, Read Models identified for each process | YES | 12 business processes with Actor → Command → Aggregate → Event → Policy flows |
| 3 | Commands have actors — every Command triggered by an explicit actor | YES | All 25 commands have named actors (User, Admin, System/Scheduler, or Policy) |
| 4 | Aggregates identified — every Command handled by a named Aggregate | YES | Every command targets a specific aggregate across 6 aggregates |
| 5 | Hot Spots documented — all disagreements, ambiguities, and unknowns captured | YES | 8 hot spots covering business rule ambiguities, technical concerns, and missing requirements |
| 6 | Hot Spots tracked — each Hot Spot either resolved or assigned to an owner | YES | All 8 hot spots resolved with owner assigned |
| 7 | Domain experts validated — reviewed and approved | PENDING | Document ready for domain expert review |
| 8 | BC candidates identified — preliminary Bounded Context groupings visible from event/language clusters | YES | 3 BC candidates confirmed, matching strategic design boundaries |

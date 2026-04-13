# Tactical Design

DDD tactical design for the pydentity identity management system, organized by bounded context. Derived from the domain model UML diagrams.

---

## Aggregate Design Principles

All aggregates in this system follow Vernon's four rules for aggregate design (Vernon, IDDD Ch. 10):

1. **Protect true invariants inside aggregate boundaries.** Each aggregate encloses only the domain objects that must be transactionally consistent together. Business rules are enforced by the aggregate root — no external code bypasses the root to mutate internal state.
2. **Design small aggregates.** Aggregates are kept as small as possible. Only EmailPasswordCredential is internal to Account (shared password history invariant). All other domain objects are separate aggregates.
3. **Reference other aggregates by identity only.** Session references Account and Device by AccountId and DeviceId — never by direct object reference. The same pattern applies across all cross-aggregate relationships.
4. **Use eventual consistency outside the boundary.** Cross-aggregate coordination uses domain events, not transactional coupling. Downstream contexts (Audit, Notification) react to events asynchronously.

---

## Concept Classification

Every domain concept is classified as Aggregate Root, Entity, Value Object, Enum, Domain Service, Domain Interface, Factory, or Repository. This table summarizes all concepts across all bounded contexts.

### Shared Kernel

| Concept | Classification | Identity | Immutable? | Rationale |
|---------|---------------|----------|:----------:|-----------|
| AccountId | Value Object | N/A | Yes | Identifier — same UUID = same account reference |
| DeviceId | Value Object | N/A | Yes | Identifier — same UUID = same device reference |
| EventName | Value Object | N/A | Yes | Classification label — attribute equality |
| ValueObject | Abstract Base | N/A | — | Abstract base for all value objects |
| DomainEvent | Abstract Base | N/A | — | Abstract base for all domain events |
| DomainError | Abstract Base | N/A | — | Abstract base for all domain errors |
| Entity\<TId\> | Abstract Base | TId | — | Abstract base for all entities |
| AggregateRoot\<TId\> | Abstract Base | TId | — | Abstract base for all aggregate roots |

### Authentication Context

| Concept | Classification | Identity | Immutable? | Rationale |
|---------|---------------|----------|:----------:|-----------|
| Account | Aggregate Root | AccountId (UUID) | No | Tracked across lifecycle, enforces authentication invariants |
| EmailPasswordCredential | Entity | CredentialId (UUID) | No | Internal to Account — shares password history invariant with root |
| Session | Aggregate Root | SessionId (UUID) | No | Independent lifecycle, no shared invariant with Account |
| Device | Aggregate Root | DeviceId (UUID) | No | Independent lifecycle, no shared invariant with Account |
| VerificationRequest | Aggregate Root | VerificationRequestId (UUID) | No | Independent lifecycle, no shared invariant with Account |
| CredentialId | Value Object | N/A | Yes | Identifier |
| Email | Value Object | N/A | Yes | Descriptive — same address = same email |
| RawPassword | Value Object | N/A | Yes | Transient input, never persisted |
| HashedPassword | Value Object | N/A | Yes | Cryptographic output |
| FailedAttemptCount | Value Object | N/A | Yes | Measurement — integer quantity |
| PasswordPolicy | Value Object | N/A | Yes | Configuration rules |
| LockoutPolicy | Value Object | N/A | Yes | Configuration rules |
| SessionId | Value Object | N/A | Yes | Identifier |
| SessionPolicy | Value Object | N/A | Yes | Configuration rules |
| RawDeviceFingerprint | Value Object | N/A | Yes | Transient input, never persisted |
| HashedDeviceFingerprint | Value Object | N/A | Yes | Cryptographic output |
| DevicePolicy | Value Object | N/A | Yes | Configuration rules |
| VerificationRequestId | Value Object | N/A | Yes | Identifier |
| RawVerificationRequestToken | Value Object | N/A | Yes | Transient input, never persisted |
| HashedVerificationRequestToken | Value Object | N/A | Yes | Cryptographic output |
| VerificationPolicy | Value Object | N/A | Yes | Configuration rules |
| AccountStatus | Enum | N/A | — | Lifecycle state |
| LockReason | Enum | N/A | — | Categorization |
| UnlockReason | Enum | N/A | — | Categorization |
| SessionStatus | Enum | N/A | — | Lifecycle state |
| SessionEndReason | Enum | N/A | — | Categorization |
| DeviceStatus | Enum | N/A | — | Lifecycle state |
| DeviceRevocationReason | Enum | N/A | — | Categorization |
| VerificationRequestStatus | Enum | N/A | — | Lifecycle state |
| VerificationRequestType | Enum | N/A | — | Categorization |
| VerificationFailureReason | Enum | N/A | — | Categorization |
| SessionExpiry | Value Object | N/A | Yes | Temporal boundary |
| VerificationRequestExpiry | Value Object | N/A | Yes | Temporal boundary |
| PasswordHasher | Domain Interface | N/A | — | Infrastructure contract — hashing strategy |
| PasswordVerifier | Domain Interface | N/A | — | Infrastructure contract — verification strategy |
| CompromisedPasswordChecker | Domain Interface | N/A | — | Infrastructure contract — breach database access |
| EmailVerifier | Domain Interface | N/A | — | Infrastructure contract — email validation |
| DeviceFingerprintHasher | Domain Interface | N/A | — | Infrastructure contract — hashing strategy |
| DeviceFingerprintVerifier | Domain Interface | N/A | — | Infrastructure contract — verification strategy |
| VerificationRequestTokenHasher | Domain Interface | N/A | — | Infrastructure contract — hashing strategy |
| VerificationRequestTokenVerifier | Domain Interface | N/A | — | Infrastructure contract — verification strategy |
| PreventDuplicateEmail | Domain Service | N/A | — | Cross-aggregate rule — verb-named |
| AuthenticateAccount | Domain Service | N/A | — | Pure verification — verb-named |
| ChangeAccountPassword | Domain Service | N/A | — | Orchestrates password change with policy enforcement — verb-named |
| ChangeAccountEmail | Domain Service | N/A | — | Orchestrates email change with validation — verb-named |
| RegisterAccount | Domain Service | N/A | — | Orchestrates account creation with validations — verb-named |
| TerminateSessions | Domain Service | N/A | — | Cross-aggregate operation — verb-named |
| RegisterDevice | Domain Service | N/A | — | Cross-aggregate operation with policy enforcement — verb-named |
| RevokeDevices | Domain Service | N/A | — | Cross-aggregate operation — verb-named |
| IssueEmailVerificationRequest | Domain Service | N/A | — | Orchestrates email verification request creation — verb-named |
| IssuePasswordResetRequest | Domain Service | N/A | — | Orchestrates password reset request creation — verb-named |
| VerifyVerificationRequestToken | Domain Service | N/A | — | Token verification with expiry checking — verb-named |

### Audit Context

| Concept | Classification | Identity | Immutable? | Rationale |
|---------|---------------|----------|:----------:|-----------|
| AuditEntry | Aggregate Root | AuditEntryId (UUID) | Yes | Append-only record, immutable after creation |
| AuditEntryId | Value Object | N/A | Yes | Identifier |
| EventPayload | Value Object | N/A | Yes | Immutable key-value pairs |

### Notification Context

| Concept | Classification | Identity | Immutable? | Rationale |
|---------|---------------|----------|:----------:|-----------|
| DeliveryRequest | Aggregate Root | DeliveryRequestId (UUID) | No | Tracked across delivery lifecycle |
| DeliveryRequestId | Value Object | N/A | Yes | Identifier |
| Recipient | Value Object | N/A | Yes | Descriptive — same address = same recipient |
| MessageContent | Value Object | N/A | Yes | Descriptive |
| AttemptCount | Value Object | N/A | Yes | Measurement — integer quantity |
| Channel | Enum | N/A | — | Categorization |
| ContentSensitivity | Enum | N/A | — | Categorization |
| DeliveryStatus | Enum | N/A | — | Lifecycle state |

---

## Shared Kernel

Shared value objects used across bounded context boundaries.

### Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| AccountId | value: UUID | Identifies an account across all contexts |
| DeviceId | value: UUID | Identifies a registered device |
| EventName | value: str | Classifies domain events for audit purposes |

### Building Blocks (Abstract Base Types)

| Name | Fields / Behavior | Purpose |
|------|-------------------|---------|
| ValueObject | — | Abstract base for all value objects |
| DomainEvent | name: EventName | Abstract base for all domain events |
| DomainError | message: str | Abstract base for all domain errors |
| Entity\<TId\> | id: TId | Abstract base for all entities |
| AggregateRoot\<TId\> | events: list[DomainEvent], record_event(), clear_events() | Abstract base for all aggregate roots, extends Entity |

---

## Authentication Context

Core context. Handles account lifecycle, credential management, sessions, devices, and verification flows.

### Account Aggregate

**Root:** Account
**Entity:** EmailPasswordCredential
**Identity:** AccountId (UUID)
**References by ID:** None (root aggregate of the context)

#### Invariants Protected

- Password cannot repeat any entry in the password history (max history depth enforced by PasswordPolicy)
- Failed attempt count must be consistent with lock status — exceeding the LockoutPolicy threshold triggers a lock
- Status transitions follow a defined state machine (no invalid transitions)
- Email must be unique across all accounts (enforced via PreventDuplicateEmail domain service)
- New password must not appear in breach databases (NIST 800-63B)
- New password must satisfy PasswordPolicy length constraints

#### Aggregate State

| Field | Type | Description |
|-------|------|-------------|
| id | AccountId | Unique account identifier |
| status | AccountStatus | Current lifecycle state |
| credentials | EmailPasswordCredential | Email/password credential |
| failed_attempt_count | FailedAttemptCount | Consecutive failed login count |

#### Entity: EmailPasswordCredential

| Field | Type | Description |
|-------|------|-------------|
| id | CredentialId | Unique credential identifier |
| email | Email | Account email address |
| hashed_password | HashedPassword | Current password hash |
| password_history | list[HashedPassword] | Previous password hashes |

**Behaviors (internal — called by Account root):**
- `_change_password(new_hash, max_history)` — Rotates password history and updates the hashed password
- `_change_email(new_email)` — Updates the email address

#### Aggregate Behaviors

| Command | Parameters | Rules |
|---------|------------|-------|
| create | account_id, credential_id, email, hashed_password | Class factory method. Sets status to PENDING_VERIFICATION |
| record_login_success | — | Resets failed attempt count. Requires ACTIVE status |
| record_login_failure | lockout_policy | Increments failed count. Locks account if threshold exceeded |
| verify_email | — | Transitions from PENDING_VERIFICATION to ACTIVE |
| change_password | new_hash, max_history | Updates password via credential entity. Requires ACTIVE status. Orchestration (policy, breach check, reuse check) is in `ChangeAccountPassword` service |
| change_email | new_email | Updates email via credential entity. Requires ACTIVE status. Validation and uniqueness checking is in `ChangeAccountEmail` service |
| lock | reason | Transitions to LOCKED with a reason (THRESHOLD or ADMIN) |
| unlock | reason | Transitions from LOCKED to ACTIVE with a reason (EXPIRY or ADMIN) |
| suspend | — | Transitions to SUSPENDED (administrative action) |
| close | — | Transitions to CLOSED (permanent) |

#### Status Transitions

```
PENDING_VERIFICATION --> ACTIVE         [verify_email]
ACTIVE               --> LOCKED         [lock]
ACTIVE               --> SUSPENDED      [suspend]
ACTIVE               --> CLOSED         [close]
LOCKED               --> ACTIVE         [unlock]
```

#### Domain Events

| Event | Key Fields | Trigger |
|-------|------------|---------|
| AccountRegistered | account_id, email | create |
| LoginSucceeded | account_id | record_login_success |
| LoginFailed | account_id, failed_attempt_count | record_login_failure |
| EmailVerified | account_id | verify_email |
| EmailChanged | account_id, old_email, new_email | change_email |
| PasswordChanged | account_id | change_password |
| AccountLocked | account_id, reason | lock |
| AccountUnlocked | account_id, reason | unlock |
| AccountSuspended | account_id | suspend |
| AccountClosed | account_id | close |

#### Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| CredentialId | value: UUID | Identifies a credential entity |
| Email | value: str | Validated email address |
| RawPassword | value: str | Plaintext password (transient, never persisted) |
| HashedPassword | value: str | Cryptographically hashed password |
| FailedAttemptCount | value: int | Consecutive failed login attempts |
| PasswordPolicy | min_length: int, max_length: int, max_history: int | Password requirements |
| LockoutPolicy | max_failed_attempts: int, lockout_duration_seconds: int | Lockout thresholds |

#### Domain Interfaces

| Name | Method | Purpose |
|------|--------|---------|
| PasswordHasher | hash(password) : HashedPassword | Hashes a raw password |
| PasswordVerifier | verify(password, hash) : bool | Verifies a raw password against a hash |
| CompromisedPasswordChecker | is_compromised(password) : bool | Checks if password appears in breach databases |
| EmailVerifier | is_valid(email) : bool | Validates whether an email address is syntactically valid |

#### Domain Services

| Name | Injected Dependencies | Purpose |
|------|----------------------|---------|
| PreventDuplicateEmail | AccountRepository | Ensures email uniqueness. Method: `ensure_unique(email)` |
| AuthenticateAccount | PasswordVerifier | Verifies password matches hash. Raises `InvalidCredentialsError` on mismatch. No aggregate mutation. Method: `authenticate(password, hashed_password)` |
| ChangeAccountPassword | PasswordVerifier, PasswordHasher, CompromisedPasswordChecker | Validates current password, checks policy, breach database, and reuse. Returns `HashedPassword`. Method: `change_password(current_password, new_password, hashed_password, password_history, policy)` |
| ChangeAccountEmail | EmailVerifier, PreventDuplicateEmail | Validates email format and uniqueness. Method: `change_email(new_email)` |
| RegisterAccount | EmailVerifier, PasswordHasher, CompromisedPasswordChecker, PreventDuplicateEmail | Orchestrates account creation with all validations. Method: `register(account_id, credential_id, email, password, policy) : Account` |

#### Repository

| Method | Description |
|--------|-------------|
| find_by_id(account_id) : Account \| None | Retrieve by identity |
| find_by_email(email) : Account \| None | Retrieve by email |
| exists_by_email(email) : bool | Check email existence |
| save(account) | Persist account state |

---

### Session Aggregate

**Root:** Session
**Identity:** SessionId (UUID)
**References by ID:** AccountId, DeviceId

#### Invariants Protected

- Session can only be ended when status is ACTIVE
- Session can only be refreshed when status is ACTIVE
- Expiration is extended (not shortened) on refresh

#### Aggregate State

| Field | Type | Description |
|-------|------|-------------|
| id | SessionId | Unique session identifier |
| account_id | AccountId | Owning account |
| device_id | DeviceId | Device this session runs on |
| status | SessionStatus | Active or Ended |
| expiry | SessionExpiry | When this session expires |

#### Aggregate Behaviors

| Command | Parameters | Rules |
|---------|------------|-------|
| create | session_id, account_id, device_id, expiry | Class factory method. Sets status to ACTIVE |
| end | reason | Transitions from ACTIVE to ENDED with a reason |
| refresh | policy, current_time | Recomputes expiration from policy and current time |

#### Domain Events

| Event | Key Fields | Trigger |
|-------|------------|---------|
| SessionStarted | session_id, account_id, device_id | create |
| SessionEnded | session_id, account_id, device_id, reason | end |
| SessionRefreshed | session_id, account_id, device_id | refresh |

#### Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| SessionId | value: UUID | Identifies a session |
| SessionPolicy | ttl_seconds: int | Session duration configuration |
| SessionExpiry | value: datetime | When a session expires |

#### Enums

| Name | Values | Purpose |
|------|--------|---------|
| SessionStatus | ACTIVE, ENDED | Session lifecycle |
| SessionEndReason | LOGOUT, EXPIRED, FORCED, COMPROMISE | Why a session ended |

#### Domain Service

| Name | Method | Purpose |
|------|--------|---------|
| TerminateSessions | terminate_active_sessions(device_sessions: list[Session], reason) | Ends all active sessions in the provided list. Caller queries sessions from repository. |

#### Repository

| Method | Description |
|--------|-------------|
| find_by_id(session_id) : Session \| None | Retrieve by identity |
| find_active_by_device_id(device_id) : list[Session] | Retrieve active sessions for a device |
| save(session) | Persist session state |

---

### Device Aggregate

**Root:** Device
**Identity:** DeviceId (UUID)
**References by ID:** AccountId

#### Invariants Protected

- Device can only be revoked when status is ACTIVE
- Active device count per account must not exceed DevicePolicy.max_devices_per_account (enforced via RegisterDevice domain service)

#### Aggregate State

| Field | Type | Description |
|-------|------|-------------|
| id | DeviceId | Unique device identifier |
| account_id | AccountId | Owning account |
| fingerprint | HashedDeviceFingerprint | Hashed device fingerprint |
| status | DeviceStatus | Active or Revoked |

#### Aggregate Behaviors

| Command | Parameters | Rules |
|---------|------------|-------|
| create | device_id, account_id, fingerprint | Class factory method. Sets status to ACTIVE |
| revoke | reason | Transitions from ACTIVE to REVOKED with a reason |

#### Domain Events

| Event | Key Fields | Trigger |
|-------|------------|---------|
| DeviceRegistered | device_id, account_id | create |
| DeviceRevoked | device_id, account_id, reason | revoke |

#### Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| RawDeviceFingerprint | value: str | Plaintext fingerprint (transient, never persisted) |
| HashedDeviceFingerprint | value: str | Cryptographically hashed fingerprint |
| DevicePolicy | max_devices_per_account: int | Device limit per account |

#### Enums

| Name | Values | Purpose |
|------|--------|---------|
| DeviceStatus | ACTIVE, REVOKED | Device lifecycle |
| DeviceRevocationReason | MANUAL, ADMIN, LOCKOUT, CLOSURE | Why a device was revoked |

#### Domain Interfaces

| Name | Method | Purpose |
|------|--------|---------|
| DeviceFingerprintHasher | hash(fingerprint) : HashedDeviceFingerprint | Hashes a raw device fingerprint |
| DeviceFingerprintVerifier | verify(fingerprint, hash) : bool | Verifies a fingerprint against a hash |

#### Domain Services

| Name | Injected Dependencies | Purpose |
|------|----------------------|---------|
| RegisterDevice | DeviceFingerprintHasher, DeviceRepository | Registers a new device, enforcing the max device limit. Method: `register(device_id, account_id, fingerprint, policy) : Device` |
| RevokeDevices | — | Revokes all active devices in the provided list. Method: `revoke_active_devices(account_devices: list[Device], reason)`. Caller queries devices from repository. |

#### Repository

| Method | Description |
|--------|-------------|
| find_by_id(device_id) : Device \| None | Retrieve by identity |
| find_by_fingerprint(fingerprint) : Device \| None | Retrieve by hashed fingerprint |
| find_by_account_id(account_id) : list[Device] | Retrieve all devices for an account |
| count_active_by_account_id(account_id) : int | Count active devices for limit enforcement |
| save(device) | Persist device state |

---

### Verification Request Aggregate

**Root:** VerificationRequest
**Identity:** VerificationRequestId (UUID)
**References by ID:** AccountId

#### Invariants Protected

- Token can only be verified when status is PENDING
- Verification rejects expired requests (checked against VerificationRequestExpiry)
- Verification rejects invalid tokens (checked via VerificationRequestTokenVerifier)
- Status transitions follow a defined state machine — PENDING is the only source state for all transitions
- Pending requests are invalidated when a new request of the same type is created for the same account (handled internally by `IssueEmailVerificationRequest` / `IssuePasswordResetRequest`)

#### Aggregate State

| Field | Type | Description |
|-------|------|-------------|
| id | VerificationRequestId | Unique request identifier |
| account_id | AccountId | Owning account |
| status | VerificationRequestStatus | Current lifecycle state |
| type | VerificationRequestType | Email verification or password reset |
| hash | HashedVerificationRequestToken | Hashed token |
| expiry | VerificationRequestExpiry | When this request expires |

#### Aggregate Behaviors

| Command | Parameters | Rules |
|---------|------------|-------|
| create | verification_request_id, account_id, request_type, hashed_token, expiry | Class factory method. Sets status to PENDING |
| verify | — | Transitions from PENDING to VERIFIED. Token and expiry checking is in `VerifyVerificationRequestToken` service |
| invalidate | — | Transitions from PENDING to INVALIDATED |
| expire | — | Transitions from PENDING to EXPIRED |

#### Status Transitions

```
PENDING --> VERIFIED      [verify (success)]
PENDING --> INVALIDATED   [invalidate]
PENDING --> EXPIRED       [expire]
```

Verification failure reasons: INVALID_TOKEN, EXPIRED, ALREADY_VERIFIED.

#### Domain Events

| Event | Key Fields | Trigger |
|-------|------------|---------|
| VerificationRequestCreated | verification_request_id, account_id, type | create |
| VerificationRequestVerified | verification_request_id, account_id | verify (success) |
| VerificationRequestFailed | verification_request_id, account_id, reason | verify (failure) |
| VerificationRequestInvalidated | verification_request_id, account_id | invalidate |
| VerificationRequestExpired | verification_request_id, account_id | expire |

#### Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| VerificationRequestId | value: UUID | Identifies a verification request |
| RawVerificationRequestToken | value: str | Plaintext token sent to user (transient) |
| HashedVerificationRequestToken | value: str | Cryptographically hashed token |
| VerificationPolicy | email_verification_ttl_seconds: int, password_reset_ttl_seconds: int | TTL configuration per request type |
| VerificationRequestExpiry | value: datetime | When a verification request expires |

#### Enums

| Name | Values | Purpose |
|------|--------|---------|
| VerificationRequestStatus | PENDING, VERIFIED, INVALIDATED, EXPIRED | Request lifecycle |
| VerificationRequestType | EMAIL_VERIFICATION, PASSWORD_RESET | Kind of verification |
| VerificationFailureReason | INVALID_TOKEN, EXPIRED, ALREADY_VERIFIED | Why verification failed |

#### Domain Interfaces

| Name | Method | Purpose |
|------|--------|---------|
| VerificationRequestTokenHasher | hash(token) : HashedVerificationRequestToken | Hashes a raw token |
| VerificationRequestTokenVerifier | verify(token, hash) : bool | Verifies a raw token against a hash |

#### Domain Services

| Name | Injected Dependencies | Purpose |
|------|----------------------|---------|
| IssueEmailVerificationRequest | VerificationRequestTokenHasher, VerificationRequestRepository | Invalidates pending email verification requests, hashes token, computes expiry, delegates to `VerificationRequest.create()`. Method: `issue(verification_request_id, account_id, raw_token, policy, current_time) : tuple[VerificationRequest, RawVerificationRequestToken]` |
| IssuePasswordResetRequest | VerificationRequestTokenHasher, VerificationRequestRepository | Invalidates pending password reset requests, hashes token, computes expiry, delegates to `VerificationRequest.create()`. Method: `issue(verification_request_id, account_id, raw_token, policy, current_time) : tuple[VerificationRequest, RawVerificationRequestToken]` |
| VerifyVerificationRequestToken | VerificationRequestTokenVerifier | Checks expiry (calls `request.expire()` if expired), verifies token against hash, calls `request.verify()` on success. Method: `verify(request, token, current_time)` |

#### Repository

| Method | Description |
|--------|-------------|
| find_by_id(verification_request_id) : VerificationRequest \| None | Retrieve by identity |
| find_pending_by_account_id(account_id) : list[VerificationRequest] | Retrieve all pending requests for an account |
| find_pending_by_account_id_and_type(account_id, request_type) : VerificationRequest \| None | Retrieve pending request by account and type (at most one) |
| save(verification_request) | Persist request state |

---

## Audit Context

Supporting context. Records immutable audit entries for domain events that occur across the system.

### Audit Entry Aggregate

**Root:** AuditEntry
**Identity:** AuditEntryId (UUID)
**References by ID:** AccountId

#### Invariants Protected

- Immutable after creation — no update or delete operations. The `record` factory method is the only way to create an entry, and no mutation methods exist.

#### Aggregate State

| Field | Type | Description |
|-------|------|-------------|
| id | AuditEntryId | Unique entry identifier |
| event_name | EventName | Name of the audited domain event |
| account_id | AccountId | Account associated with the event |
| payload | EventPayload | Key-value pairs with event context |

#### Aggregate Behaviors

| Command | Parameters | Rules |
|---------|------------|-------|
| record | id, event_name, account_id, payload | Static factory method. Creates an immutable audit record |

#### Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| AuditEntryId | value: UUID | Identifies an audit entry |
| EventPayload | entries: tuple[tuple[str, str], ...] | Immutable key-value pairs with event details |

#### Repository

| Method | Description |
|--------|-------------|
| find_by_id(entry_id) : AuditEntry \| None | Retrieve by identity |
| find_by_account_id(account_id) : list[AuditEntry] | Retrieve all entries for an account |
| find_by_event_name(event_name) : list[AuditEntry] | Retrieve all entries for an event type |
| save(entry) | Persist audit entry |

---

## Notification Context

Supporting context. Manages message delivery to users across channels, with retry handling and sensitive content purging.

### Delivery Request Aggregate

**Root:** DeliveryRequest
**Identity:** DeliveryRequestId (UUID)
**References by ID:** AccountId

#### Invariants Protected

- Status transitions follow a defined state machine — only PENDING can transition to SENT or FAILED
- Content is purged only for deliveries marked as SENSITIVE and only after status is SENT
- Attempt count is monotonically increasing

#### Aggregate State

| Field | Type | Description |
|-------|------|-------------|
| id | DeliveryRequestId | Unique request identifier |
| account_id | AccountId | Target account |
| recipient | Recipient | Delivery address |
| channel | Channel | Delivery method (Email or SMS) |
| content | MessageContent \| None | Message subject and body. None after purging |
| status | DeliveryStatus | Current delivery state |
| attempt_count | AttemptCount | Number of delivery attempts |
| sensitivity | ContentSensitivity | Whether content must be purged after delivery |

#### Aggregate Behaviors

| Command | Parameters | Rules |
|---------|------------|-------|
| create | id, account_id, recipient, channel, content, sensitivity | Static factory method. Sets status to PENDING, attempt count to 0 |
| mark_sent | — | Transitions from PENDING to SENT |
| record_failed_attempt | — | Increments the attempt count |
| mark_failed | — | Transitions to FAILED (permanent failure) |
| purge_content | — | Clears message content for sensitive deliveries after sending |

#### Status Transitions

```
PENDING --> SENT     [mark_sent]
PENDING --> FAILED   [mark_failed]
```

#### Domain Events

| Event | Key Fields | Trigger |
|-------|------------|---------|
| MessageDelivered | delivery_request_id, account_id | mark_sent |
| MessageDeliveryFailed | delivery_request_id, account_id | mark_failed |

#### Value Objects

| Name | Fields | Purpose |
|------|--------|---------|
| DeliveryRequestId | value: UUID | Identifies a delivery request |
| Recipient | address: str | Delivery address |
| MessageContent | subject: str \| None, body: str | Message content |
| AttemptCount | value: int | Delivery attempt counter |

#### Enums

| Name | Values | Purpose |
|------|--------|---------|
| Channel | EMAIL, SMS | Delivery method |
| ContentSensitivity | SENSITIVE, STANDARD | Whether content requires purging |
| DeliveryStatus | PENDING, SENT, FAILED | Delivery lifecycle |

#### Repository

| Method | Description |
|--------|-------------|
| find_by_id(request_id) : DeliveryRequest \| None | Retrieve by identity |
| find_pending() : list[DeliveryRequest] | Retrieve all pending deliveries |
| find_failed() : list[DeliveryRequest] | Retrieve all failed deliveries |
| find_sensitive_requiring_purge() : list[DeliveryRequest] | Retrieve sent sensitive deliveries needing content purge |
| save(request) | Persist delivery request state |

---

## Domain Event Catalog

Unified catalog of all domain events across bounded contexts, showing producers, consumers, and cross-boundary flow.

### Authentication Events

| Event | Produced By | Consumed By | Cross-Boundary? |
|-------|------------|-------------|:---------------:|
| AccountRegistered | Account | Audit, Notification | Yes |
| LoginSucceeded | Account | Audit | Yes |
| LoginFailed | Account | Audit | Yes |
| EmailVerified | Account | Audit | Yes |
| EmailChanged | Account | Audit | Yes |
| PasswordChanged | Account | Audit, Notification | Yes |
| AccountLocked | Account | Audit, Notification | Yes |
| AccountUnlocked | Account | Audit | Yes |
| AccountSuspended | Account | Audit | Yes |
| AccountClosed | Account | Audit, Notification | Yes |
| SessionStarted | Session | Audit | Yes |
| SessionEnded | Session | Audit | Yes |
| SessionRefreshed | Session | — | No |
| DeviceRegistered | Device | Audit, Notification | Yes |
| DeviceRevoked | Device | Audit | Yes |
| VerificationRequestCreated | VerificationRequest | Audit, Notification | Yes |
| VerificationRequestVerified | VerificationRequest | Audit | Yes |
| VerificationRequestFailed | VerificationRequest | Audit | Yes |
| VerificationRequestInvalidated | VerificationRequest | Audit | Yes |
| VerificationRequestExpired | VerificationRequest | Audit | Yes |

### Notification Events

| Event | Produced By | Consumed By | Cross-Boundary? |
|-------|------------|-------------|:---------------:|
| MessageDelivered | DeliveryRequest | — | No |
| MessageDeliveryFailed | DeliveryRequest | — | No |

### Audit Events

Audit produces no domain events. The audit entry itself is the record.

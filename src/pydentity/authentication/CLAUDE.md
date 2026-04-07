# Authentication Context

Core domain — all other contexts depend on this one (one-way).

## Aggregates

Six aggregates: Identity, Account, Session, TrustedDevice, AuthenticationAttempt, RecoveryRequest.

## Rules

- **No cross-aggregate mutations.** Aggregates never call methods on other aggregates. Use domain events for cross-aggregate reactions (e.g., AccountLocked → force-end Sessions, revoke TrustedDevices). Application services orchestrate these reactions.
- **Pure domain logic.** Aggregates receive pre-built value objects and `now: datetime`. No infrastructure dependencies (hashing, encryption, token generation) inside aggregates — that belongs in the application layer.
- **Password policy is injected.** PasswordPolicy is not stored on Account. It is passed into register, change_password, and reset_password behaviors.
- **Password reuse prevention via domain service.** `PreventPasswordReuse.check()` validates against current password and history (max 24). Never check reuse inside the aggregate.
- **Email uniqueness via domain service.** `PreventDuplicateEmail.check()` queries the repository. Never enforce uniqueness inside the aggregate.
- **Device limit via domain service.** `EnforceDeviceLimit.check()` counts active devices against DevicePolicy. Never enforce limits inside the aggregate.
- **Hashed secrets only.** Passwords, refresh tokens, recovery tokens, recovery codes, and verification codes are stored as one-way hashes. TOTP secret is the sole exception — it is encrypted (not hashed) because the service must read the raw value for validation.
- **Access token is not a domain concept.** It is stateless, signed, and belongs to the application/infrastructure layer. Never model it in the domain.
- **Verification codes belong to AuthenticationAttempt.** They are generated on demand during an attempt, stored hashed within the attempt, and never reused across attempts.
- **Account status lifecycle.** UNVERIFIED → ACTIVE → LOCKED/SUSPENDED → CLOSED. CLOSED is terminal. ACTIVE ↔ LOCKED is bidirectional. Respect guards in every behavior method.
- **MFA is orthogonal.** MFA enablement requires at least one non-password credential (TOTP or unused recovery codes). Cannot remove the last non-password credential while MFA is enabled.

# Authentication Service — Event Storming Walkthrough

## Final Validation of the Domain Model

This document traces every user-facing scenario through the full chain: **Command → Aggregate → Behavior → Domain Event → Reaction.** All 23 scenarios passed validation.

---

## Scenario 1: Registration

```
COMMAND: Register (Email Address, Password)
  │
  ▼
AGGREGATE: Identity (via `Identity.create()` classmethod)
  BEHAVIOR: Create Identity
  EVENT: Identity Created
    → Audit: Record Event
  │
  ▼
AGGREGATE: Account (via `Account.register()` classmethod)
  BEHAVIOR: Register (Identity ID, Email Address, Password, Password Policy injected)
  PRECONDITIONS: Email unique. Password satisfies policy.
  EVENT: Account Registered
    → Audit: Record Event
  EVENT: Email Verification Requested
    → Audit: Record Event
    → Notification: Deliver verification link via Email
  │
  ▼
RESULT: Account in Unverified status. Person cannot authenticate yet.
```

---

## Scenario 2: Email Verification

```
COMMAND: Verify Email (Account ID, verification proof)
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Verify Email
  PRECONDITION: Account must be Unverified
  EVENT: Email Verified
    → Audit: Record Event
  │
  ▼
RESULT: Account Status → Active. Person can now authenticate.
```

---

## Scenario 3: Login (No MFA)

```
COMMAND: Login (Email Address, Password)
  │
  ▼
APPLICATION SERVICE: Authenticate Identity
  ├─ Looks up Account by Email Address
  ├─ Checks Account Status = Active
  ├─ Checks Trusted Device status — not relevant without MFA
  │
  ▼
AGGREGATE: Authentication Attempt (via `AuthenticationAttempt.initiate()` classmethod)
  BEHAVIOR: Initiate (MFA disabled)
  Required Factors = [Knowledge]
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Validate Credential (Password) → Valid
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Verify Factor (Knowledge) → all factors verified
  EVENT: Authentication Succeeded
    → Account: Record Successful Attempt (reset counter)
    → Audit: Record Event
    → `Session.start()`: Create Session
        │
        ▼
      AGGREGATE: Session
        BEHAVIOR: Start
        Refresh Token hashed and stored. Access Token generated as output.
        EVENT: Session Started → Audit: Record Event
  │
  ▼
RESULT: Authenticated. Access Token returned. Refresh Token stored hashed.
```

---

## Scenario 4: Login (MFA with TOTP)

```
COMMAND: Login (Email Address, Password)
  │
  ▼
APPLICATION SERVICE: Authenticate Identity
  ├─ Account Status = Active, MFA Enabled = true
  ├─ Device not trusted
  │
  ▼
AGGREGATE: Authentication Attempt (via `AuthenticationAttempt.initiate()` classmethod)
  BEHAVIOR: Initiate (MFA enabled, device not trusted)
  Required Factors = [Knowledge, Possession]
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Validate Credential (Password) → Valid
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Verify Factor (Knowledge) → Verified Factors = [Knowledge]
  Still In Progress.
  │
  ── Person presents TOTP code ──
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Validate Credential (TOTP) → decrypts secret, validates → Valid
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Verify Factor (Possession) → all factors verified
  EVENT: Authentication Succeeded
    → Account: Record Successful Attempt
    → Audit: Record Event
    → `Session.start()`: Create Session → Session Started
  │
  ▼
RESULT: Authenticated with both factors.
```

---

## Scenario 5: Login (MFA with Email/SMS Verification Code)

```
COMMAND: Login (Email Address, Password)
  │
  ▼
APPLICATION SERVICE: Authenticate Identity
  ├─ MFA Enabled = true, no TOTP — Possession Factor via email/SMS
  ├─ Device not trusted
  │
  ▼
AGGREGATE: Authentication Attempt (via `AuthenticationAttempt.initiate()` classmethod)
  BEHAVIOR: Initiate
  Required Factors = [Knowledge, Possession]
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Validate Credential (Password) → Valid
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Verify Factor (Knowledge) → verified
  BEHAVIOR: Set Verification Code → hashes and stores code
  EVENT: Verification Code Generated (raw code + recipient address)
    → Audit: Record Event
    → Notification: Deliver code via Email or SMS
  │
  ── Person receives and presents code ──
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Verify Factor (Possession) → hashes input, compares → Valid
  All factors verified.
  EVENT: Authentication Succeeded
    → Account: Record Successful Attempt
    → Audit: Record Event
    → `Session.start()`: Create Session
  │
  ▼
RESULT: Authenticated via email/SMS code.
```

---

## Scenario 6: Login (MFA with Trusted Device — MFA Relaxed)

```
COMMAND: Login (Email Address, Password, Device Fingerprint)
  │
  ▼
APPLICATION SERVICE: Authenticate Identity
  ├─ MFA Enabled = true
  ├─ Device found as Trusted (Registered, not expired)
  ├─ Policy: MFA relaxed for Trusted Device
  │
  ▼
AGGREGATE: Authentication Attempt (via `AuthenticationAttempt.initiate()` classmethod)
  BEHAVIOR: Initiate (MFA enabled, device IS trusted)
  Required Factors = [Knowledge] (Possession relaxed by policy)
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Validate Credential (Password) → Valid
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Verify Factor (Knowledge) → all factors verified
  EVENT: Authentication Succeeded
    → Account: Record Successful Attempt
    → Audit: Record Event
    → `Session.start()`: Create Session
  │
  ▼
RESULT: Authenticated with single factor. Trusted Device relaxed MFA.
```

---

## Scenario 7: Login Failed (Wrong Password)

```
COMMAND: Login (Email Address, wrong Password)
  │
  ▼
APPLICATION SERVICE: Authenticate Identity
  │
  ▼
AGGREGATE: Authentication Attempt (via `AuthenticationAttempt.initiate()` classmethod)
  BEHAVIOR: Initiate
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Validate Credential (Password) → INVALID
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Fail
  EVENT: Authentication Failed
    → Account: Record Failed Attempt (increment counter)
    → Audit: Record Event
  │
  ▼
RESULT: Login denied. Counter incremented. No Session, no Token.
```

---

## Scenario 8: Login Failed — Account Lockout Cascade

```
COMMAND: Login (wrong Password) — Nth consecutive failure
  │
  ... same as Scenario 7 until ...
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Record Failed Attempt → counter reaches threshold
  BEHAVIOR: Lock
  EVENT: Account Locked
    → Audit: Record Event
    → Application layer orchestration (Terminate Sessions):
        AGGREGATE: Session (each active)
          BEHAVIOR: End → Refresh Token revoked
          EVENT: Session Ended → Audit: Record Event
    → Application layer orchestration (Revoke Trusted Devices):
        AGGREGATE: Trusted Device (each Registered)
          BEHAVIOR: Revoke
          EVENT: Trusted Device Revoked → Audit: Record Event
  │
  ▼
RESULT: Account Locked. All Sessions ended. All Trusted Devices revoked.
```

---

## Scenario 9: Token Refresh

```
COMMAND: Refresh Token (Refresh Token value)
  │
  ▼
AGGREGATE: Session (found via Refresh Token hash)
  PRECONDITIONS: Session Active. Refresh Token valid, not expired.
  BEHAVIOR: Refresh
  New Access Token generated (returned, not stored).
  Optional: Refresh Token rotated (old revoked, new stored hashed).
  EVENT: Refresh Token Rotated → Audit: Record Event
  │
  ▼
RESULT: New Access Token returned. Session continues.
```

---

## Scenario 10: Logout

```
COMMAND: Logout (Session ID)
  │
  ▼
AGGREGATE: Session
  BEHAVIOR: End
  Refresh Token marked as revoked.
  EVENT: Session Ended → Audit: Record Event
  │
  ▼
RESULT: Session ended. Refresh Token revoked. Access Token expires naturally (5–15 min).
```

---

## Scenario 11: Password Reset (Full Three-Step Flow)

```
── Step 1: Request ──

COMMAND: Request Password Reset (Email Address)
  │
  ▼
APPLICATION SERVICE: Recover Account
  ├─ Looks up Account
  ├─ Invalidates any existing pending Recovery Request
  │
  ▼
AGGREGATE: Recovery Request (via `RecoveryRequest.create()` classmethod)
  BEHAVIOR: Create
  Recovery Token: raw for delivery, hash stored.
  EVENT: Password Reset Requested → Audit: Record Event
  EVENT: Recovery Token Issued
    → Audit: Record Event
    → Notification: Deliver raw token via Email


── Step 2: Verify ──

COMMAND: Verify Recovery Token (raw token)
  │
  ▼
APPLICATION SERVICE: Recover Account
  ├─ Hashes token, looks up Recovery Request
  │
  ▼
AGGREGATE: Recovery Request
  BEHAVIOR: Verify → token not expired
  EVENT: Recovery Token Verified → Audit: Record Event


── Step 3: Complete Reset ──

COMMAND: Complete Password Reset (Recovery Request ID, new Password)
  │
  ▼
APPLICATION SERVICE: Recover Account
  ├─ Recovery Request must be Verified
  ├─ Looks up Account
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Reset Password (Password Policy injected)
  Old hash added to history. New password hashed.
  EVENT: Password Reset Completed
    → Audit: Record Event
    → Application layer orchestration (Terminate Sessions): End all active Sessions
        EVENT: Session Ended (per session) → Audit
  │
  ▼
AGGREGATE: Recovery Request
  BEHAVIOR: Complete → Status = Completed
  EVENT: Recovery Request Completed → Audit: Record Event
  │
  ▼
RESULT: Password replaced. All Sessions terminated. No Session created.
Person must login normally.
```

---

## Scenario 12: Add TOTP Secret

```
COMMAND: Add TOTP Secret (Account ID, Encrypted TOTP Secret)
  │
  ▼
AGGREGATE: Account
  PRECONDITIONS: Active. No existing active TOTP credential.
  BEHAVIOR: Add TOTP Secret (encrypted at rest)
  EVENT: TOTP Secret Added → Audit: Record Event
  │
  ▼
RESULT: TOTP credential added. MFA can now be enabled.
```

---

## Scenario 13: Add Recovery Codes

```
COMMAND: Add Recovery Codes (Account ID, HashedRecoveryCodeSet)
  │
  ▼
AGGREGATE: Account
  BEHAVIOR: Add Recovery Codes (hashes stored, replacing any existing set)
  EVENT: Recovery Codes Generated → Audit: Record Event
  │
  ▼
RESULT: Raw codes shown once. Only hashes retained. MFA can now be enabled.
```

---

## Scenario 14: Enable MFA

```
COMMAND: Enable MFA (Account ID)
  │
  ▼
AGGREGATE: Account
  PRECONDITIONS: Active. At least one non-Password credential exists.
  BEHAVIOR: Enable MFA
  EVENT: MFA Enabled → Audit: Record Event
  │
  ▼
RESULT: MFA Enabled = true. Future logins require multiple factors.
```

---

## Scenario 15: Disable MFA

```
COMMAND: Disable MFA (Account ID)
  │
  ▼
AGGREGATE: Account
  PRECONDITION: Active.
  BEHAVIOR: Disable MFA
  EVENT: MFA Disabled → Audit: Record Event
  │
  ▼
RESULT: MFA Enabled = false. Future logins require only Password.
```

---

## Scenario 16: Change Password

```
COMMAND: Change Password (Account ID, current password, new password)
  │
  ▼
AGGREGATE: Account
  PRECONDITIONS: Active. Current password valid. New password satisfies policy.
  New password not in Password History.
  BEHAVIOR: Change Password
  Old hash added to history. New password hashed.
  EVENT: Password Changed
    → Audit: Record Event
    → Application layer orchestration (Terminate Sessions): End all active Sessions
        EVENT: Session Ended (per session) → Audit
  │
  ▼
RESULT: Password updated. All Sessions terminated. Person must re-authenticate.
```

---

## Scenario 17: Register Trusted Device

```
COMMAND: Trust Device (Account ID, Device Fingerprint)
  │
  ▼
DOMAIN SERVICE: Enforce Device Limit
  Counts Registered devices. At maximum → reject or revoke oldest.
  │
  ▼
AGGREGATE: Trusted Device
  BEHAVIOR: Register
  PRECONDITION: Account Active.
  EVENT: Device Trusted → Audit: Record Event
  │
  ▼
RESULT: Device registered. Future logins may relax MFA.
```

---

## Scenario 18: Revoke Trusted Device (Manual)

```
COMMAND: Revoke Device (Device ID)
  │
  ▼
AGGREGATE: Trusted Device
  PRECONDITION: Status = Registered.
  BEHAVIOR: Revoke
  EVENT: Trusted Device Revoked → Audit: Record Event
  │
  ▼
RESULT: Device no longer trusted.
```

---

## Scenario 19: Account Suspension

```
COMMAND: Suspend Account (Account ID)
  │
  ▼
AGGREGATE: Account
  PRECONDITION: Active or Locked.
  BEHAVIOR: Suspend
  EVENT: Account Suspended
    → Audit: Record Event
    → Application layer orchestration (Terminate Sessions): End all Sessions
        EVENT: Session Ended (per session) → Audit
  │
  ▼
RESULT: Account Suspended. All Sessions ended.
```

---

## Scenario 20: Account Closure

```
COMMAND: Close Account (Account ID)
  │
  ▼
AGGREGATE: Account
  PRECONDITION: Not already Closed.
  BEHAVIOR: Close
  EVENT: Account Closed
    → Audit: Record Event
    → Application layer orchestration (Terminate Sessions): End all Sessions
        EVENT: Session Ended (per session) → Audit
    → Application layer orchestration (Revoke Trusted Devices): Revoke all devices
        EVENT: Trusted Device Revoked (per device) → Audit
  │
  ▼
RESULT: Account Closed. All Sessions ended. All Devices revoked. Identity persists.
```

---

## Scenario 21: Account Unlock

```
COMMAND: Unlock Account (Account ID)
  │
  ▼
AGGREGATE: Account
  PRECONDITION: Must be Locked.
  BEHAVIOR: Unlock
  Counter reset.
  EVENT: Account Unlocked → Audit: Record Event
  │
  ▼
RESULT: Account Active. Trusted Devices remain revoked (must be re-registered).
```

---

## Scenario 22: Recovery Token Expires

```
  ── Time passes ──
  │
  ▼
AGGREGATE: Recovery Request
  BEHAVIOR: Expire
  EVENT: Password Reset Expired → Audit: Record Event
  │
  ▼
RESULT: Request expired. Person must request a new Password Reset.
```

---

## Scenario 23: Authentication Attempt Expires (MFA Abandoned)

```
  ── Person never completes second factor ──
  │
  ▼
AGGREGATE: Authentication Attempt
  BEHAVIOR: Expire
  Status → Expired. No downstream event. Silently discarded.
  │
  ▼
RESULT: Attempt gone. No counter increment. No Session. Start over.
```

---

## Validation Summary

| # | Scenario | Result |
|---|----------|--------|
| 1 | Registration | Pass |
| 2 | Email Verification | Pass |
| 3 | Login (No MFA) | Pass |
| 4 | Login (MFA with TOTP) | Pass |
| 5 | Login (MFA with Email/SMS Code) | Pass |
| 6 | Login (MFA with Trusted Device) | Pass |
| 7 | Login Failed (Wrong Password) | Pass |
| 8 | Login Failed — Account Lockout Cascade | Pass |
| 9 | Token Refresh | Pass |
| 10 | Logout | Pass |
| 11 | Password Reset (Full Flow) | Pass |
| 12 | Add TOTP Secret | Pass |
| 13 | Add Recovery Codes | Pass |
| 14 | Enable MFA | Pass |
| 15 | Disable MFA | Pass |
| 16 | Change Password | Pass (terminates all Sessions) |
| 17 | Register Trusted Device | Pass |
| 18 | Revoke Trusted Device | Pass |
| 19 | Account Suspension | Pass |
| 20 | Account Closure | Pass |
| 21 | Account Unlock | Pass |
| 22 | Recovery Token Expires | Pass |
| 23 | Authentication Attempt Expires | Pass |

**23 scenarios. 23 passed. 0 issues remaining.**

---

## Session Termination Trigger Summary

| Event | Terminates Sessions | Revokes Trusted Devices |
|-------|--------------------|-----------------------|
| Account Locked | Yes | Yes |
| Account Suspended | Yes | No |
| Account Closed | Yes | Yes |
| Password Changed | Yes | No |
| Password Reset Completed | Yes | No |

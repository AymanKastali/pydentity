# Notification Context

Generic subdomain — Conformist relationship with Authentication.

## Aggregate

Single aggregate: DeliveryRequest.

## Rules

- **Async delivery only.** DeliveryRequests are created from Authentication events via a translation layer. Actual delivery happens asynchronously — never during request creation.
- **Terminal status states.** PENDING → SENT or PENDING → FAILED. Both SENT and FAILED are terminal — no reverse transitions. PENDING → PENDING (retry) is valid.
- **Sensitive content purge.** Requests carrying raw tokens or verification codes (`is_sensitive=True`) must have their content purged after successful delivery or timeout. The record itself is retained; only the content field is cleared to None.
- **No delivery feedback to Authentication.** MessageDelivered and MessageDeliveryFailed events are internal to Notification. Authentication never learns whether delivery succeeded. This is intentional — bidirectional dependency would couple Core Domain to Generic Subdomain.
- **Only three Authentication events trigger delivery.** EmailVerificationRequested (email, not sensitive), VerificationCodeGenerated (email/SMS, sensitive), RecoveryTokenIssued (email, sensitive).
- **Templates are infrastructure.** Transforming event data into human-readable MessageContent (localization, HTML/text formatting) belongs in the infrastructure layer, not the domain.
- **Retry policy is infrastructure.** Max retries, backoff intervals, and channel fallback strategy are configured outside the domain.

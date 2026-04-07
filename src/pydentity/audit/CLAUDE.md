# Audit Context

Supporting subdomain — Conformist relationship with Authentication.

## Aggregate

Single aggregate: AuditEntry.

## Rules

- **Append-only.** AuditEntry is immutable after creation. No update or delete operations exist in the domain. Repository exposes only `save()` and read methods.
- **No PII in payloads.** EventPayload contains only identifiers (AccountId, SessionId, AttemptId) and metadata (reason codes, factor types, credential types). Never store email addresses, phone numbers, names, or raw credential values.
- **Terminal consumer.** Audit consumes Authentication events but produces zero domain events. No information flows back to Authentication.
- **Event type as string.** Event names are stored as plain strings, not structured enums. This decouples Audit from Authentication schema changes.
- **Payload constraints.** Max 50 entries per payload. Keys max 100 chars. Values max 500 chars. Enforced at construction via guards.
- **Retention and access control are infrastructure concerns.** Archival strategy, compliance (SOC 2, GDPR), rate limiting, and consumer scoping belong in the infrastructure layer, not the domain.

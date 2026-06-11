# ADR-009: Audit Logging

## Context

The application is required to capture audit events from NFR-S5, concretely:

- **Authentication:** `LOGIN`, `LOGIN_FAILED`, `LOGOUT`
- **User lifecycle:** `USER_CREATED`, `ROLE_CHANGED`, `USER_DISABLED`
- **Submissions:** `SUBMISSION_CREATED`
- **Analyses:** `ANALYSIS_STARTED`, `ANALYSIS_COMPLETED`, `ANALYSIS_FAILED`
- **Reviews:** `REVIEW_CREATED`

Each entry: `id`, `userId`, `eventType`, `details` (JSON), `createdAt`. Already defined in the domain model.

## Decision

- **Layer:** Every service method that performs a security-relevant action explicitly writes an audit event.
- **Sync vs async:** Writes are synchronous and in the same database transaction as the action they log. This guarantees consistency: if the main action commits, the audit event commits; if it rolls back, both roll back. Async patterns (outbox table, durable queue) are the correct approach when log processing is expensive or when scale demands it, but deliver no benefit at MVP scale and are deferred as future work.
- **Immutability:** Audit event table is append-only; no update or delete operations are exposed.

## Consequences

- All audit events come from one place: the services layer.
- Events are captured consistently; if the action fails, nothing is written in the audit table.
- Once events are written, they are read-only. In future versions, there will be restrictions on the table itself.
- Modest per-action overhead (one DB insert per logged event); negligible at MVP scale but would matter at high request volumes. Addressable in the future via outbox pattern when needed.

## Rejected alternatives

- **Middleware-only logging:** Captures HTTP route + user, but not domain-level intent ("role changed from X to Y", "analysis failed because LLM timed out"). Insufficient granularity.
- **External logging service (Sentry, CloudWatch):** Useful for ops/observability but not a substitute for a tamper-resistant audit trail. Future work.
- **Async/background logging:** Lower latency but risks log loss; unacceptable for an accountability NFR.

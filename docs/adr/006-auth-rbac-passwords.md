# ADR-006: Authentication, RBAC, and Password Storage

## Context

Authentication and RBAC are NFRs. The requirements are 3 different roles with different permissions. There are 3 decisions to make here: how users authenticate, where role checks happen, and how passwords/tokens are managed.

## Decision

- **Authentication:** Users authenticate with passwords once. A JWT token is generated and renewed every 30 minutes. To avoid retyping passwords on every access, tokens are refreshed every week.
- **Authorization:** Role checks are made using FastAPI dependencies, so every route checks the role before responding.
- **Password storage:** Argon2 via passlib — industry standard and well-supported.

## Consequences

- Stateless authentication; no server-side session store needed. Tokens are verified by signature on each request.
- Role required by each route is visible at the route definition.
- Token revocation is non-trivial, mitigated by short-lived tokens and weekly refresh.
- Password verification is timing-safe by default using the library.

## Rejected alternatives

- **Session cookies:** Requires server-side storage; mismatched with stateless single-process MVP and FastAPI conventions.
- **RBAC in every handler / in middleware:** Both repetitive or disconnected from route definitions.
- **SHA-256 / plain hash for passwords:** Can be easily defeated by rainbow table and GPU brute-force.

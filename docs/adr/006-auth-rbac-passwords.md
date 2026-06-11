# ADR-006: Authentication, RBAC, and password storage

## Context
Authentication and RBAC are non-functional requirements (NFR-S2, NFR-S3).
The system requires three distinct roles (Developer, Auditor, Admin) with
different permissions. Three decisions must be made: how users authenticate,
where role checks happen, and how passwords are stored. Additionally, role
assignment itself must be controlled to prevent privilege escalation, and
the first administrator must be created via a secure bootstrap mechanism.

## Decision

### Authentication
Users authenticate with email and password once; the server issues a
**JWT access token** (30-minute lifetime) and a **refresh token**
(7-day lifetime). Subsequent requests carry the access token in the
`Authorization: Bearer <token>` header. When the access token expires,
the client exchanges the refresh token for a new access token without
prompting the user.

### RBAC enforcement
Role checks are implemented as **FastAPI dependencies**
(`Depends(require_role(...))`) attached to each protected route. The
dependency runs before the route handler; if the user does not hold the
required role, the request is rejected with HTTP 403 and the handler is
never invoked. The required role is therefore visible at the route
definition itself, acting as machine-checkable documentation.

### Password storage
Passwords are hashed with **Argon2** via the `passlib` library. Argon2
is the modern recommendation (winner of the Password Hashing Competition),
is deliberately slow and memory-hard to resist GPU brute-force, and
handles salt generation and timing-safe comparison automatically.

### Role assignment & bootstrap
- **New user registration:** new users are automatically assigned the
  `Developer` role. The role field is not user-selectable on the
  registration form.
- **Role promotion:** changing a user's role (to Auditor or Admin)
  requires an authenticated Admin and is performed via the Admin
  User Management interface. Every role change generates an immutable
  `ROLE_CHANGED` AuditEvent (NFR-S5).
- **Auditor-Developer assignment:** an Admin explicitly assigns one or
  more Developers to each Auditor via the `AuditorAssignment` table.
  Auditors can only review findings from developers assigned to them.
- **First-admin bootstrap:** at application startup, if no Admin exists
  in the database, one is automatically created from
  `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` environment
  variables. Once at least one Admin exists, the bootstrap is skipped
  on subsequent startups — the env vars do not override existing
  admins. The initial password is expected to be rotated at first
  login (future work: enforce via a `must_change_password` flag).

## Consequences
- Stateless authentication — no server-side session store needed;
  tokens are verified by signature on each request.
- The required role for each endpoint is visible at the route
  definition, readable and self-documenting.
- Token revocation before expiry is non-trivial; mitigated by short
  access-token lifetime + refresh token rotation.
- Password verification is timing-safe by default via the library.
- Role assignment is fully under Admin control after bootstrap,
  preventing privilege escalation via self-registration.
- The first-admin bootstrap mechanism is idempotent and runs only
  when the system is in a "no-admin" state, preventing accidental
  override of an existing administrator.

## Rejected alternatives
- **Session cookies.** Requires server-side session storage; mismatched
  with the stateless single-process MVP and FastAPI conventions.
- **RBAC enforced in every handler / in middleware.** Both work but
  are either repetitive (handler-level — easy to forget) or
  disconnected from route definitions (middleware — hard to read).
  FastAPI dependencies give locality and enforceability.
- **SHA-256 / fast hash for passwords.** Rejected — fast hashes are
  defeated by rainbow tables and GPU brute-force. Password-specific
  hashes (Argon2, bcrypt) are deliberately slow to resist this.
- **User-selectable role at registration.** Rejected — allows trivial
  privilege escalation. Any attacker could register as Admin and
  compromise the system.
- **Email-based admin recovery / no bootstrap.** Rejected for MVP —
  would require email infrastructure (out of MVP scope per ADR-008
  rationale). Env-var bootstrap is the standard self-hosted pattern
  (used by WordPress, GitLab, Discourse).

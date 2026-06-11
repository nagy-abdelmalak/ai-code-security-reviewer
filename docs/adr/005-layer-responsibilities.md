# ADR-005: Layer Responsibilities

## Context

ADR-002 chose a layered architecture. The responsibilities of each layer and the dependency rules between them must be defined explicitly to prevent business logic from leaking into HTTP handlers or ORM models, which would compromise testability and security boundaries.

## Decision

The four main layers are:

- **Presentation (`/api`):** Handles the user request, transforming every request into valid schema using Pydantic
- **Services (`/services`):** Receives valid schemas, runs all configured analyzers, stores findings and writes audit events
- **Domain (`/models`, `/schemas`):** Where the mapping of ORM models and Pydantic schemas happens
- **Infrastructure (`/core`, `/db`, `/analyzers`):** Manages database sessions, config loading, password hashing, JWT helpers, the analyzer port and its adapters

Dependency rule: `api` may depend on `services`; `services` may depend on `models`, `schemas`, and infrastructure. The reverse is forbidden. Services never import from `api`; models never import from `services`.

## Consequences

- Business logic lives in one obvious place (services), testable without the HTTP layer.
- Security checks (auth, RBAC, audit) are centralized; impossible to forget per endpoint.
- Models and schemas separated; the API cannot accidentally leak fields like `passwordHash`.
- Cost: boilerplate of converting between request schema → model → response schema for every feature.

## Rejected alternatives

- **Anemic single-file app:** Fast to start, unmaintainable beyond ~200 lines; business logic, auth, and persistence become entangled and untestable.
- **Active Record / fat models:** Business logic on model classes (Django-style); rejected because cross-entity logic (analysis + audit + notification) has no clean home, and security checks become scattered.

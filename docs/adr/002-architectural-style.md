# ADR-002: Architectural Style

## Context

The MVP must be delivered by a single developer, satisfy security/RBAC NFRs, and support the thesis comparison between static and LLM analysers.

## Decision

Adopt a layered (n-tier) architecture with a Ports & Adapters pattern for the Analyzer subsystem and four layers: presentation, service, domain, infrastructure.

The Analyzer subsystem: an abstract `Analyzer` interface with `SemgrepAnalyser` and `LLMAnalyser` implementations. The service layer depends only on the interface, enabling swap and comparison.

## Consequences

- Simple structure, clear ownership that maps to FastAPI conventions
- Outer layers coupled to FastAPI and SQLAlchemy — accepted for project scope
- Analyzer subsystem is genuinely swappable
- Service classes risk growing large, mitigated by one service per domain entity

## Rejected alternatives

- **Hexagonal architecture:** Overkill for MVP scope, but partially adopted for Analyzer only
- **Microservices:** Solves multi-team/independent-deploy problems in enterprise contexts; this doesn't apply here

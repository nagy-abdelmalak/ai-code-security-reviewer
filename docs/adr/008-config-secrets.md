# ADR-008: Configuration & Secrets

## Context

The application requires sensitive values (LLM API key, JWT secret, database URL) and non-sensitive configuration (token TTLs, Semgrep ruleset, log level). Secrets must never reach source control; all configuration must be type-validated at startup.

## Decision

Configuration is loaded via Pydantic `BaseSettings` from environment variables. In development, values are read from a local `.env` file (gitignored). In production, values are injected by the container runtime. A `.env.example` is committed as a template showing every required variable with placeholder values. Missing required values fail fast at app startup.

## Consequences

- Secrets are safe and never committed to git; gitignored from day one.
- Industry-standard pattern; plays well with Docker, Kubernetes, and CI/CD.
- Pydantic adds type validation.
- Small operational tax: deployers must set environment variables correctly when running the container; missing values fail fast at startup rather than at runtime.

## Rejected alternatives

- **Hardcoded values in code:** Catastrophic the moment you push to GitHub — there are bots scraping commit history for leaked API keys within minutes. Non-starter.
- **A committed `config.yaml` or `settings.py` with real values:** Same problem, different file extension. Rejected for the same reason.
- **A secret manager (Vault, AWS Secrets Manager, Doppler):** Proper production approach but overkill for MVP. Adds infrastructure, latency, and a learning curve. Mention as future work.

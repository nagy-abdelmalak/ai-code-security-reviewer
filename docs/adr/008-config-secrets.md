# ADR-008: Configuration & secrets

## Context
The application requires sensitive values (LLM API key, JWT secret,
database URL) and non-sensitive configuration (token TTLs, semgrep
ruleset, log level). It also requires the initial administrator
credentials (`INITIAL_ADMIN_EMAIL`, `INITIAL_ADMIN_PASSWORD`) used
for the first-admin bootstrap defined in ADR-006. Secrets must never
reach source control; all configuration must be type-validated at
startup.

## Decision
Configuration is loaded via Pydantic `BaseSettings` from environment
variables. In development, values are read from a local `.env` file
(gitignored). In production, values are injected by the container
runtime (e.g., Docker Compose, Kubernetes). A `.env.example` file
is committed as a template showing every required variable with
placeholder values. Missing required values fail fast at app startup
with clear error messages.

The `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` variables are
read by the application startup logic to bootstrap the first Admin
user (see ADR-006). These are *startup-time* secrets: they are only
consulted when no Admin exists in the database. They MUST be rotated
after first login.

## Consequences
- Secrets are never committed to source control; `.env` is gitignored
  from day one.
- Twelve-Factor App aligned; plays naturally with Docker, Kubernetes,
  and CI/CD pipelines.
- Pydantic provides type validation and immediate startup failure
  for missing or malformed values, preventing runtime surprises.
- Bootstrap credentials are sensitive only at deployment time;
  rotation after first login is operationally required to prevent
  long-lived static admin credentials from being a persistent risk.
- Small operational tax: deployers must set environment variables
  correctly when running the container; missing values fail fast at
  startup rather than at runtime.

## Rejected alternatives
- **Hardcoded values in code.** Catastrophic the moment code is
  pushed to GitHub — there are bots scraping commit history for
  leaked API keys within minutes. Non-starter.
- **A committed `config.yaml` or `settings.py` with real values.**
  Same problem, different file extension. Rejected for the same
  reason.
- **A secret manager (Vault, AWS Secrets Manager, Doppler).** Proper
  production approach but overkill for MVP — adds infrastructure,
  latency, and a learning curve. Documented as future work.

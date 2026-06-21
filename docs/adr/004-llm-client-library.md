# ADR-004: LLM Client Library

## Context

The `LLMAnalyser` adapter (see ADR-002, ADR-003) must call LLM providers and support swapping models or providers as a thesis requirement.

Options: a unifying library (LangChain) or each provider's native SDK.

## Decision

The LLM provider is selected at deployment time via a single environment variable `LLM_PROVIDER`. The application uses LangChain's init_chat_model universal factory, which resolves the provider-specific client at runtime. Switching from OpenAI to Anthropic requires zero code changes.

## Consequences

- Provider swap is a one-line config change — directly supports the thesis.
- Built-in prompt templating, retries, and structured output parsing reduce custom code.
- Heavy dependency footprint and larger Docker image.
- LangChain's API is unstable across versions; pinned to a fixed minor version to avoid mid-project breakage.
- Some behavior (default retries, message formatting) is implicit; must be audited for thesis-grade experimental control.

## Rejected alternatives

- **Raw provider SDKs (e.g. `openai`, `anthropic`):** Lighter and more explicit, but every new provider requires writing a new client from scratch. Rejected because thesis-level swappability is a primary requirement.

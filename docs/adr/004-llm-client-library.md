# ADR-004: LLM Client Library

## Context

The `LLMAnalyser` adapter (see ADR-002, ADR-003) must call LLM providers and support swapping models or providers as a thesis requirement.

Options: a unifying library (LangChain) or each provider's native SDK.

## Decision

Use LangChain inside the `LLMAnalyser` adapter. Provider choice (OpenAI, Anthropic, local Ollama) becomes a configuration concern, not a code change. Prompt templates are managed through LangChain's `PromptTemplate`, versioned via the `promptVersion` field on Analysis.

## Consequences

- Provider swap is a one-line config change — directly supports the thesis.
- Built-in prompt templating, retries, and structured output parsing reduce custom code.
- Heavy dependency footprint and larger Docker image.
- LangChain's API is unstable across versions; pinned to a fixed minor version to avoid mid-project breakage.
- Some behavior (default retries, message formatting) is implicit; must be audited for thesis-grade experimental control.

## Rejected alternatives

- **Raw provider SDKs (e.g. `openai`, `anthropic`):** Lighter and more explicit, but every new provider requires writing a new client from scratch. Rejected because thesis-level swappability is a primary requirement.

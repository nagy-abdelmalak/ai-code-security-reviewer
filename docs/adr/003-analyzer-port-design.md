# ADR-003: Analyzer Port

## Context

ADR-002 establishes a Ports & Adapters pattern for the Analyzer subsystem. The port itself must be defined: its interface, its inputs/outputs, its error model. The interface must fit both static analyzers and LLM analyzers (API call), and must let the service layer treat them uniformly.

## Decision

Define a Python `Protocol` named `Analyzer` with a single method:

```python
class Analyzer(Protocol):
    name: str
    version: str
    async def analyze(self, code: str, language: str) -> AnalysisResult: ...
```

`AnalysisResult` is a dataclass containing:

- `findings`: `list[Finding]`
- `status`: enum `[completed, failed]`
- `errorMessage`: `str | None`
- `durationMs`: `int`

Failures are reported through the result object, not raised as exceptions (analysers must not crash the service layer).

## Consequences

- Async-first interface; concurrent analyzer execution and non-blocking request handling supported.
- Service layer iterates over analyzers uniformly; comparing Semgrep and LLM is a simple loop.
- The `name` and `version` attributes map directly to `Analysis.analyzerType` and `Analysis.promptVersion` in the domain model.
- Returning failures (instead of raising) keeps the service layer simple and supports NFR-R1 (graceful degradation when LLM unavailable).

## Rejected alternatives

- **Exceptions for failure:** Idiomatic Python, but forces every caller to wrap analyzer calls in try/except. The result-object approach makes the failure path explicit and uniform.
- **Multiple methods (`analyze` + `validate` + `describe`):** Larger surface area, no current consumer for the extra methods. YAGNI.

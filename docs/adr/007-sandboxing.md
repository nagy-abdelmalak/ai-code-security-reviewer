# ADR-007: Sandboxing Untrusted Code

## Context

User code is treated as untrusted data, as explained in NFR-S4. The system must run a static analyzer (Semgrep) on user Python code without exposing the host to the risk of possible execution, file system, or process compromise. Defense-in-depth required.

## Decision

- **Static-only tool (non-exec):** Semgrep performs static analysis; user code is parsed as data and never executed.
- **Input validation:** Only `.py` files (for the MVP) are accepted with maximum 1MB size; non-text content will be rejected.
- **Filesystem isolation:** For every static analysis request, a separate file with a unique UUID and `0600` permissions is created in a dedicated folder outside the root folder and deleted after analysis (by context manager or `finally` block).
- **Process isolation:** Semgrep is invoked via `asyncio.create_subprocess_exec` with a list-style argument vector (never `shell=True`), wrapped in a 30-second timeout via `asyncio.wait_for`. Memory limits via `resource.setrlimit` provide additional protection against algorithmic-complexity attacks.
- **Containerization:** The application runs in a Docker container as a non-root user, providing an outer boundary against container escape. Stronger isolation (rootless analyzer container) documented as future work.
- **LLM disclosure:** Users are informed that LLM analysis transmits their code to a third-party provider. LLM analysis is toggle-able per submission, allowing privacy-conscious use of static analysis only.

## Consequences

- Multi-layer defense; no single bypass compromises the system.
- Modest overhead per request.
- Stronger isolation deferred as future work.
- LLM disclosure shifts confidentiality responsibility to the user.

## Rejected alternatives

- **Running Semgrep in-process via the Python API:** Semgrep is designed as a CLI; in-process invocation would mean parser crashes take down the web server.
- **Executing user code (dynamic analysis):** Out of scope and a massive attack surface — would require full sandbox technology we don't have time to implement.
- **No isolation, just `subprocess.run`:** Current `main.py` approach. No timeout, no cleanup, no defense-in-depth narrative — works for a prototype, fails the security NFR.

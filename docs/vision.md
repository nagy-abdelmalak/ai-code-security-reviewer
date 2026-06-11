# Vision

AI Code Security Reviewer is a web-based tool that analyzes source code for security vulnerabilities by combining traditional static analysis with LLM-based review. Initially designed for individual developers, with long-term goals of supporting teams and security auditors.

Its distinctive purpose is to enable a direct, empirical comparison between deterministic static analysis and probabilistic AI-driven review — both as a practical aid to developers and as a research instrument.

## MVP Scope

- **Language:** Python only (multi-language = documented future work)
- **Interface:** Web UI with REST API underneath
- **Static analyzer:** Semgrep (multi-language-ready, industry standard)
- **AI analyzer:** One LLM via API, accessed through a swappable port abstraction
- **Output:** Side-by-side comparison of both reports
- **Roles:** Developer, Security Auditor, Admin (RBAC)

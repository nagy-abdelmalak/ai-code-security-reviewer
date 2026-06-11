# Non-Functional Requirements

## Security

- **NFR-S1:** Confidentiality
- **NFR-S2:** Authentication
- **NFR-S3:** Authorization
- **NFR-S4:** Input safety
- **NFR-S5:** Accountability
- **NFR-S6:** Secrets handling
- **NFR-S7:** HTTPS in production

## Performance

- **NFR-P1:** Semgrep ≤500 lines under 5s
- **NFR-P2:** LLM under 30s or timeout

## Reliability

- **NFR-R1:** Graceful degradation if LLM fails

## Maintainability

- **NFR-M1:** Swappable analyzer abstraction
- **NFR-M2:** PEP 8 + linter

## Usability

- **NFR-U1:** Human-readable errors

## Portability

- **NFR-Po1:** Docker container with documented env vars

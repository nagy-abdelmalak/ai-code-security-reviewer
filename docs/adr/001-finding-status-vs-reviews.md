# ADR-001: Separating Finding Status from Review Thread

## Context

A Finding may receive zero or more verdicts from auditors over time. We considered three options:

1. One Review per Finding with verdict embedded
2. Many Reviews per Finding with no separate status field (compute current state from latest)
3. One status field on Finding plus many Reviews as discussion annotations

## Decision

Adopt option (3). Finding carries a `status` field representing its current verdict. Review represents an auditor annotation with an optional `proposedStatus`. A service-layer rule keeps them consistent: when a Review with a non-null `proposedStatus` is created, `Finding.status` is updated.

## Consequences

- Querying "all unreviewed high-severity findings" is a single-table query — fast and simple.
- The full audit thread is preserved as Review records.
- Two pieces of state must be kept consistent, which is the service layer's responsibility.
- Future support for comment-only reviews and multi-auditor discussion is trivial.

## Rejected alternatives

- **Option 1 (one Review per Finding):** Too restrictive; loses discussion history.
- **Option 2 (compute status from latest review):** Every read of `Finding.status` requires a join and an ordering — slow at scale, complex in code.

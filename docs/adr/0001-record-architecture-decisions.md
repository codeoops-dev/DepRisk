# ADR 0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

DepRisk combines several technologies (a .NET core, a Rust analyzer, an Ada/SPARK kernel, an optimization layer) and makes security-relevant claims. Future contributors, reviewers, and users need to understand *why* choices were made, not only what the code does. Decisions made only in chat or in memory get lost.

## Decision

We record significant architecture decisions as Architecture Decision Records in `docs/adr/`, one file per decision, numbered sequentially: `NNNN-short-title.md`.

An ADR is required for changes to:

- architecture or component boundaries,
- trust boundaries and the threat model,
- public contracts (CLI commands, exit codes, `schemaVersion`ed formats),
- the audit-log format or cryptography,
- the properties proven by the verification kernel,
- the choice of languages, solvers, or storage.

ADRs are immutable once accepted. To change a decision, add a new ADR that supersedes the old one and update the old one's status to `Superseded by NNNN`.

## Template

Copy this section into a new file.

```markdown
# ADR NNNN: Title

- **Status:** Proposed | Accepted | Superseded by NNNN | Rejected
- **Date:** YYYY-MM-DD

## Context
What problem or force makes this decision necessary? Constraints, alternatives considered.

## Decision
What we decided, stated plainly.

## Consequences
Positive and negative results, trade-offs, follow-up work, and what would make us revisit it.
```

## Consequences

- Small overhead per significant change, in exchange for a durable record.
- Reviewers can challenge a decision in a pull request against the ADR rather than in scattered discussions.

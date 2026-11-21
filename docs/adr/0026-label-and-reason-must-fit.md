# ADR 0026: An analyzer answer's label and reason must fit together

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

ADR 0023 closed one way a faulty or replaced analyzer could make a finding quieter: `unreachable` for a symbol list that is not declared complete. It named a second gap as a known limit: the CLI checked that the label and the reason of an analyzer answer were each known, but not that they belong together. An answer such as `unreachable` with the reason `static-path` says two opposite things at once, and which half is true cannot be told. `unreachable` is the only label that lowers a rank, exempts a finding from a gate, or can become an OpenVEX `not_affected`.

## Decision

**The protocol parser refuses a contradictory answer.** `ReachProtocol.ParseResult` now checks every result against `ReachLabels.ReasonsFor(label)`, the reasons the analyzer can give with each label (read from the analyzer's own code, `analyzers/reach/src/reach.rs`):

| Label | Reasons that fit |
|---|---|
| `reachable` | `static-path` |
| `possibly-reachable` | `dynamic-path` |
| `unreachable` | `no-path` |
| `unknown` | `no-symbols`, `no-entrypoints`, `symbol-list-incomplete`, `incomplete-analysis`, `unresolved-reflection`, `unresolved-receiver` |

Any other pair (27 of the 36) makes the whole analyzer output invalid: `AnalyzerException` ("the label and the reason do not fit together"), exit code 5 and nothing printed as a verdict, the same as any other result that breaks the protocol (an unknown label, a duplicate key, keys that do not match the request).

**Refused, not repaired.** ADR 0023 could change an `unreachable` to `unknown` because the CLI knew the one fact that made it wrong. Here the CLI cannot know which half of the pair is true, so no repair is safe; one wrong field already means the analyzer cannot be relied on for the rest of the answer.

**The two CLI-only reasons stay outside the table.** `transitive-package-code-not-analyzed` and `no-analyzer-for-ecosystem` are added by the CLI after the analyzer has answered; an analyzer that sends them is refused as before (they are not in the analyzer's reason list).

## Consequences

- A faulty or substituted analyzer can no longer pair a quieting label with a reason that contradicts it; ADR 0023's first known limit is closed.
- The real analyzer is checked against the table by the `reach-e2e` job (it drives the real binary through the CLI), so a reason added to the analyzer without a row here fails CI rather than a user. The table must be updated together with the analyzer (a new reason is also a new entry in `ReachLabels.AnalyzerReasons`).
- No schema, protocol version, or analyzer change.

## Known limits

- It checks the pairing, not what else an answer carries: that a `reachable` answer has a path, or that an `unknown` has none, is not checked (the analyzer's code gives them, but a rule that would reject a valid empty path of a one-method program needs the analyzer's rules, and has not been added).
- A faulty analyzer can still answer `unreachable` with `no-path` wrongly; the benchmark harness measures that (ADR 0017, ADR 0023).

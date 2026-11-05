# ADR 0014: Reachability in `rank` and `ci`

- **Status:** Accepted
- **Date:** 2026-11-05

## Context

`deprisk reach` (ADR 0013) computes a reachability verdict per finding. The people who gate builds use `rank` and `ci`. They need the verdict where they already look, and they need to use it in a policy. Two things must not happen: a policy that mentions reachability and silently matches nothing because no analysis ran, and the ranking changing its meaning without anyone deciding it.

## Decision

**Optional, explicit.** `rank` and `ci` accept the reachability options of `reach` (`--symbols`, `--source`, `--analyzer`, `--entrypoints`, `--entrypoint`, `--timeout`). Without `--symbols` nothing changes: no analyzer is looked up, the output is as before (the new JSON properties are null). The other options without `--symbols` are an input error, not ignored.

**Reachability is information, not part of the order.** The baseline ranking (KEV, then EPSS, then CVSS, then severity, then id) is a defined reference method that the later uncertainty model is compared with. Its order is unchanged by the verdicts, and a test pins that. The verdict is shown in the table, in the JSON (`findings[].reachability`: label, reason, symbol; top-level `reach`: analyzer, symbol maps, source, summary), and in SARIF (`properties.reachability` and `properties.reachabilityReason`). The path stays in `deprisk reach`. A null verdict means "not analyzed", never "unreachable".

**Policy terms** (`--fail-on`): `reachable`, `possibly-reachable`, `reach-unknown`, `unreachable`, and `not-unreachable` (reachable, possibly reachable, or unknown). `not-unreachable` is the safe gate: only what is proven unreachable passes. A term on reachability is false for a finding without a verdict, like any missing signal. If the policy contains a reachability term and `--symbols` is missing, the command stops with an input error before doing anything: an expression that cannot be evaluated is not a passing gate.

**One matching.** When `--symbols` is given, the reachability analysis matches the advisories first and the ranking reuses those findings, so both describe exactly the same findings. The audit record's inputs digest covers both parts (the ranking inputs and the reachability inputs: symbol maps, analyzer hash, source digest, entrypoint choices). An analyzer failure fails the command: a ranking is not printed without the verdicts that were asked for.

**Schema.** `ranking.v1` gains `findings[].reachability` and `reach`, both nullable (additive; the version stays 1).

## Known limits

- The gate sees one verdict per finding, computed for the whole source tree (ADR 0012); it cannot say in which project a path exists.
- `unknown` is common while symbol maps are sparse; `not-unreachable` then behaves like "everything that has no complete symbol list". That is the intended direction, and it is why symbol data matters more than the gate syntax.
- Reachability is not exploitability.
- The uncertainty model will decide how verdicts and signals combine; until then they sit side by side.

## Consequences

- A team can start with `kev&fixable,cvss>=9` and tighten it to `kev&fixable,cvss>=9&not-unreachable` once symbol maps exist for the advisories they care about, without a second tool.
- SARIF consumers can filter or sort on `reachability`.

# ADR 0008: SARIF output and the CI policy gate

- **Status:** Accepted
- **Date:** 2026-10-30

## Context

A finding list is only useful in a pipeline if (a) code-scanning platforms such as GitHub can show it, and (b) the build can be stopped by a rule the team controls. README promised `deprisk ci` with policy gates and SARIF. Both must stay honest: only terms that exist today may be offered, and the output must stay deterministic and safe to consume.

## Decision

### SARIF 2.1.0

- `deprisk rank` and `deprisk ci` accept `--format sarif`. The document is built from the ranking result, so findings appear **in priority order** and carry the same signals.
- **One rule per advisory** (id = advisory id, `helpUri` = `https://osv.dev/vulnerability/<escaped id>`), **one result per finding** (a package version that an advisory affects), with one location per distinct project file that uses it.
- **Locations are repository-relative.** The project file is derived from the assets file's location (`src/App/obj/project.assets.json` plus the file name stored in the assets file gives `src/App/App.csproj`). The assets file also stores an absolute, machine-specific path; only its **file name** is kept, so no developer or runner path is ever emitted. If the project file cannot be determined, the assets file path is used. Results use `uriBaseId: %SRCROOT%` and `startLine: 1` (a dependency problem has no meaningful line).
- **Levels:** `error` if the finding is in the CISA KEV catalog or its rating is critical or high (the CVSS rating when a v3 vector exists, otherwise the database rating); `warning` for medium or moderate and for unknown ratings (unknown is not treated as harmless); `note` for low. Rules carry `security-severity` (the CVSS base score) when known, which GitHub uses to rate alerts.
- **`partialFingerprints.deprisk/v1`** is a SHA-256 over advisory id, package id (lower case), and version, stable across runs, so alerts do not churn when the ranking changes.
- Deterministic: no timestamps, no invocation times, no absolute paths. The run records the method and the digests of the advisory, EPSS, and KEV data in `properties`.
- **Untrusted text** (summaries, aliases, package names) is cleaned of control characters and bounded before it enters messages and rule text; ids and paths are percent-escaped in URIs.
- **Validation:** CI validates the real output against the official OASIS SARIF 2.1.0 JSON schema. The schema is fetched by the workflow and **pinned by its SHA-256**, so an upstream change fails the build loudly instead of silently changing what we test against.

### Policy gate (`deprisk ci --fail-on <expression>`)

- Language: clauses separated by `,` (any clause may fail the gate), each clause terms joined by `&` (all must hold for the same finding). Terms: `any`, `kev`, `ransomware`, `direct`, `fixable`, `cvss>=N` / `cvss>N`, `epss>=P` / `epss>P`, `severity>=LEVEL`.
- **Strict:** unknown terms, malformed or out-of-range numbers, and terms that cannot be evaluated yet (`reachable`) are **input errors (exit 4)**, never ignored. A typo must not turn a gate into a pass. This also keeps the README honest: reachability and quantile terms appear only when v0.2 provides the data.
- **A missing signal never satisfies a comparison**, even a trivial one (`cvss>=0` is false for a finding without a CVSS score).
- **Exit codes:** 0 passed (or no policy set: a note says the gate was not evaluated), 1 gate failed, 4 invalid input. The verdict, with the first ten tripped findings, goes to **standard error**, so `--format json|sarif` on standard output stays valid. With `--out`, the file is written even when the gate fails (the pipeline can still upload it).
- **The decision is audited:** the audit entry of a `ci` run records the expression and the result (`passed` or `failed (N finding(s))`) as a change `policy gate: <expression> -> <result>`.

### Not done on purpose

- No "new findings only" or baseline suppression (needs stored history; planned with the local store).
- No OpenVEX output yet (needs reachability verdicts, v0.2).
- No GitHub Action wrapper yet; the README shows the workflow.
- Message wording and rule text are stable but not part of the schema contract; the SARIF structure is.

## Consequences

- Teams get a working gate today with signals that exist (exploitation, severity, fixability, directness), expressed in one line.
- Because the gate language rejects what it cannot evaluate, adding reachability terms later is additive and safe.
- SARIF consumers see stable fingerprints and relative paths, so alerts attach to real files in the repository.
- The `findings` and `ranking` locations gained a `projectFile` field (additive, same `schemaVersion`); `scan` gained `projectFile` per project.

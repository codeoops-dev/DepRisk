# Threat Model

Status: **living document, pre-alpha.** Mitigations marked *designed* are part of the architecture but not yet implemented; see the README [Feature status](../README.md#feature-status) table for what exists today.

## 1. Purpose and scope

DepRisk is a CLI that reads project files (lockfiles, SBOMs, source code) and signed data bundles, computes risk and remediation plans, optionally edits manifests, and records an audit log. This document states what we protect, from whom, and how.

In scope: the CLI, the reachability analyzer, the verification kernel, the audit log, bundle handling, and the `apply` command.
Out of scope: the security of the user's own build system, package registries, and operating system.

## 2. Assets

| Asset | Why it matters |
|---|---|
| **Integrity of results** (rankings, plans) | A manipulated result can cause users to skip a real fix or apply a harmful change. |
| **Integrity of the audit log** | It is the evidence of what was decided and changed. |
| **User source code and project metadata** | May be confidential; must not leave the machine. |
| **Signing keys** (audit key, bundle keys) | Compromise breaks trust in logs and data. |
| **Host environment** | DepRisk must not be a path to code execution or file tampering. |
| **Data bundles** (advisories, EPSS, KEV, symbol maps) | Poisoned data can hide or fabricate risk. |

## 3. Adversaries

| Adversary | Capability |
|---|---|
| **Malicious project** | Controls lockfiles, SBOMs, and source code that DepRisk parses (for example, a hostile dependency or a pull request from an untrusted contributor in CI). |
| **Malicious or compromised data source** | Supplies tampered advisory, EPSS, KEV, or symbol data, or a tampered bundle in transit. |
| **Local attacker with file access** | Can modify the local store or audit log after the fact. |
| **Network attacker** | Can intercept or modify downloads (install, bundle creation). |
| **Careless insider** | Can apply an unreviewed plan or misconfigure policy. |

## 4. Trust boundaries

1. **Untrusted → analyzer.** Source code and manifests cross into the Rust analyzer. The analyzer is memory-safe and runs without executing the scanned code.
2. **Untrusted → core.** Bundle contents cross into the C# core only after signature verification.
3. **Optimizer → kernel.** The optimizer is *untrusted*; only plans accepted by the SPARK kernel may be applied.
4. **Core → filesystem.** `apply` writes only to manifest/lockfile paths inside the project and the local store.
5. **Optional validation sandbox.** `apply --validate` runs project commands; this crosses into execution of project-controlled code and is isolated in a user-configured sandbox.

## 5. Threats and mitigations

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T1 | Crafted lockfile, SBOM, or source triggers memory corruption or resource exhaustion in parsers | Memory-safe analyzer; bounded input sizes, depth, and time limits; fuzzing of parsers | designed |
| T2 | Scanned project is executed during analysis | Analysis is static only; no build, no scripts, no plugins from the project | designed |
| T3 | Path traversal or symlink tricks cause writes outside the project | Canonicalize paths; refuse writes outside project root; no following of symlinks on write | designed |
| T4 | Poisoned or downgraded data bundle hides a vulnerability | Mandatory signature verification; version and freshness checks; unsigned bundles rejected unless explicitly overridden (and logged) | designed |
| T5 | Network tampering during bundle creation or install | TLS plus signature verification; checksums for release artifacts | designed |
| T6 | Audit log is edited, truncated, or reordered | Hash chain, ECDSA P-256 signatures, strict canonical form, `deprisk audit verify` (with `--head` pinning to detect removal from the end); Merkle checkpoints planned | implemented (checkpoints designed) |
| T7 | Audit key theft allows forged entries | Key generated locally with owner-only permissions (Unix), excluded from Git by `.deprisk/.gitignore`; head pinning outside the machine; guidance to keep keys off shared hosts | partly implemented (external checkpoint export designed) |
| T8 | Optimizer bug or manipulation yields an inconsistent plan | Independent proven kernel checks P1–P6 before `apply` | designed |
| T9 | `apply --validate` runs hostile project code | Runs only inside a user-configured sandbox; disabled by default; failure rolls back; actions logged | designed |
| T10 | Source code or findings leak off the machine | No telemetry, no network calls in analysis commands; LLM explanation is optional and local-first; nothing sent unless the user configures an endpoint | designed |
| T11 | Secrets appear in logs or reports | Never log source contents or secrets; redaction in diagnostics | designed |
| T12 | False reassurance from "unreachable" labels | Conservative over-approximation; `unknown` and `possibly-reachable` are never treated as safe; labels carry evidence | designed |
| T13 | Policy misconfiguration silently weakens gates | Config validation; `deprisk doctor` warnings; policy changes recorded in audit log | designed |
| T14 | Supply-chain compromise of DepRisk itself | Signed releases and checksums; pinned and reviewed dependencies; reproducible builds as a goal; Trusted Publishing for packages | designed |
| T15 | Hostile or poisoned advisory data: oversized or zip-bomb archives, symlinks leading outside the directory, ranges crafted to hide a vulnerability, terminal control sequences in text fields | Bounded reading (records, per-record and total bytes, measured on real decompressed bytes), zip entries never extracted, symlinks not followed, strict record parsing with invalid records counted and reported (`--strict` to fail), digest of the data recorded in results and audit entries, control characters stripped from table output, JSON escaped. Signed bundles (v0.5) add provenance | implemented (signed bundles designed) |
| T16 | False assurance from incomplete or stale advisory data | Output always states the source, record counts, what was skipped, and that matching is by version only; "no findings" is worded as "only as complete as the data supplied"; data freshness policy planned with bundles | implemented (freshness policy designed) |
| T17 | Hostile or stale EPSS/KEV data reorders priorities (hides an urgent finding, inflates a harmless one) or attacks the reader (gzip bomb, control characters in metadata) | Data sets are user-supplied local files; every result carries the data's file name, SHA-256, and its own published version and date; sizes are bounded on real decompressed bytes; malformed rows counted and reported (`--strict` fails); metadata printed through control-character stripping; unavailable data is `null`, never zero. Signed bundles and a freshness policy are planned (v0.5) | implemented (signed bundles, freshness policy designed) |
| T18 | SARIF and policy gate abuse: control characters or markup from advisory text in a SARIF file consumed by other tools; a weak or silently ignored `--fail-on` lets a vulnerable build pass; paths that leak the developer's machine | Advisory text cleaned of control characters and bounded before it enters messages and rule text; ids and paths percent-escaped in URIs; paths are repository-relative (the absolute path stored in assets files is reduced to a file name); the gate language is small and strict: unknown terms, out-of-range numbers, and unavailable terms (`reachable`) are errors (exit 4), never ignored; a missing signal never satisfies a comparison; the gate decision is recorded in the audit log | implemented |
| T19 | Hostile package names or ranges (control characters, quotes, backslashes, very long text) used to inject statements into exported graphs (Graphviz DOT) or to attack the terminal; dependency ranges crafted to hide a violation | DOT identifiers and labels are cleaned of control characters, bounded, and written as escaped quoted strings (verified in tests, including by the Graphviz parser); table output goes through the terminal-safe cleaner; ranges are parsed strictly (NuGet intervals, node-semver for npm) and an unparsable range, a tag, URL, git or file specifier, or a requirement that nothing resolves makes the requirement *undecided*, listed in the output, never "satisfied"; npm package names are additionally validated when the lock file is read (T20) | implemented |
| T20 | Hostile `package-lock.json`: crafted package names or keys (control characters, quotes, path tricks, very long text), duplicate keys, deep nesting, huge files; alias, link, and git entries that make a package appear to be something it is not; a lock file with the wrong format version read as if it were supported | Bounded reading (file size, JSON depth); every package and dependency name is validated against what npm can write and rejected, never copied raw, when invalid; duplicate keys rejected; unsupported or missing `lockfileVersion` is an error (exit 4), never a guess; aliases are matched by their real name; workspace links and first-party entries are not looked up as packages; `node_modules` and symlinks are not entered when searching; versions that are not strict SemVer are counted as skipped, never matched. Known limit: a package installed from a git URL or tarball is matched by name and version like a registry package (ADR 0010) | implemented |
| T21 | Hostile source code given to the reachability analyzer: parser resource exhaustion (huge files, deep nesting, many files, slow parses), symlinks that lead outside the tree, crafted names in the request or in diagnostics, a crash or hang taking the CLI down; and the opposite failure, a wrong "unreachable" that hides a real problem | The analyzer is a separate process with a JSON protocol and its own limits (file count and size, total size, per-file parse timeout, bounded walking depth and request size); symlinks are never followed and build-output directories are skipped; symbols in requests are validated against C# identifier syntax and text in messages is reduced to printable ASCII; every limit that is hit is reported and turns a missing path into `unknown`, never `unreachable`; `unreachable` additionally needs a complete symbol list, no unreadable reflection, and no unresolved receiver that could hide a path (ADR 0012). Known limit: the call graph is a model, and reachability is not exploitability | implemented (analyzer) |
| T22 | Hostile or careless symbol maps and a hostile analyzer binary: a map that hides a flaw (a short symbol list marked complete), crafted advisory, package, symbol, or source text, oversized or deeply nested files; a program planted where the analyzer is looked up; an analyzer result that lies about its structure | Symbol maps are validated strictly (size, depth, count, identifier syntax, `complete` and `source` required with no default) and a bad map fails the command instead of being skipped; the provenance (`source`) is shown with every verdict; a missing path is `unknown` unless the list is declared complete, the package is direct, and the analysis was complete (ADR 0012, 0013); the analyzer is found only through `--analyzer`, `DEPRISK_REACH`, or next to the CLI, never through `PATH`; its SHA-256 and the hash of the analyzed sources and of the maps are in the result and in the audit record; its output is parsed field by field against the protocol, keys matched to the request, text from it is shown only after control characters are removed; it runs without a shell and under a time and output limit. Known limit: a map is a claim DepRisk cannot check | implemented |
| T23 | Hostile or careless inputs to the risk model: a parameters file that is misspelled, out of range, huge, or deeply nested; sample counts or finding counts that exhaust time or memory; a "calibrated" result that is really the placeholders; results that cannot be reproduced | The parameters file is strict (unknown properties are errors, never ignored), range-checked (finite, positive, within bounds), limited to 1 MB and depth 8; samples are bounded (100 to 200,000) and findings times samples is capped at 100 million scenarios; every result states `calibration` (`uncalibrated-defaults` or `custom`) and carries a digest and a copy of the parameters; the generator is specified and pinned by a test, every finding has its own stream, the seed and its source are recorded, and the audit record covers parameters, samples, seed, and statistic (ADR 0015). Known limit: the parameters are placeholders until calibrated, and floating-point library functions may differ in the last bits across platforms | implemented |

## 6. Residual risks and non-goals

- **Reachability is an approximation.** Dynamic features (reflection, dynamic loading, eval-like constructs) can hide or invent paths. DepRisk labels these cases rather than hiding them; it does not claim soundness for all programs.
- **The kernel proves consistency, not optimality or reachability correctness.** See the README's Formal verification section.
- **Heuristic cost and exploit models.** Effort and exploit probabilities are estimates with stated uncertainty.
- **A compromised host defeats local guarantees.** If an attacker controls the machine and the audit key, they can forge entries; use external checkpointing for stronger assurance.
- **Data quality.** Garbage in the upstream advisory ecosystem produces degraded output.

## 7. Review

This model is reviewed whenever a new input type, command, or trust boundary is added (an ADR is required for such changes) and before each minor release. Security-relevant pull requests must state which threat(s) they affect.

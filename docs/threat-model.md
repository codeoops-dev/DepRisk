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
| T6 | Audit log is edited, truncated, or reordered | Hash chain, Ed25519 signatures, Merkle checkpoints; `deprisk audit verify` | designed |
| T7 | Audit key theft allows forged entries | Key generated locally with restrictive permissions; support for exporting checkpoints to write-once storage; guidance to keep keys offline | designed |
| T8 | Optimizer bug or manipulation yields an inconsistent plan | Independent proven kernel checks P1–P6 before `apply` | designed |
| T9 | `apply --validate` runs hostile project code | Runs only inside a user-configured sandbox; disabled by default; failure rolls back; actions logged | designed |
| T10 | Source code or findings leak off the machine | No telemetry, no network calls in analysis commands; LLM explanation is optional and local-first; nothing sent unless the user configures an endpoint | designed |
| T11 | Secrets appear in logs or reports | Never log source contents or secrets; redaction in diagnostics | designed |
| T12 | False reassurance from "unreachable" labels | Conservative over-approximation; `unknown` and `possibly-reachable` are never treated as safe; labels carry evidence | designed |
| T13 | Policy misconfiguration silently weakens gates | Config validation; `deprisk doctor` warnings; policy changes recorded in audit log | designed |
| T14 | Supply-chain compromise of DepRisk itself | Signed releases and checksums; pinned and reviewed dependencies; reproducible builds as a goal; Trusted Publishing for packages | designed |

## 6. Residual risks and non-goals

- **Reachability is an approximation.** Dynamic features (reflection, dynamic loading, eval-like constructs) can hide or invent paths. DepRisk labels these cases rather than hiding them; it does not claim soundness for all programs.
- **The kernel proves consistency, not optimality or reachability correctness.** See the README's Formal verification section.
- **Heuristic cost and exploit models.** Effort and exploit probabilities are estimates with stated uncertainty.
- **A compromised host defeats local guarantees.** If an attacker controls the machine and the audit key, they can forge entries; use external checkpointing for stronger assurance.
- **Data quality.** Garbage in the upstream advisory ecosystem produces degraded output.

## 7. Review

This model is reviewed whenever a new input type, command, or trust boundary is added (an ADR is required for such changes) and before each minor release. Security-relevant pull requests must state which threat(s) they affect.

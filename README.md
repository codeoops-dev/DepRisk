<div align="center">

<img src="docs/assets/deprisk-logo.svg" alt="DepRisk logo" width="120" height="120">

# DepRisk

**Stop triaging CVEs by CVSS score. Start fixing the ones that can actually hurt you, with a plan you can prove is safe.**

A command-line framework for **risk-aware, uncertainty-driven prioritization and safe remediation of software dependency vulnerabilities**, built on reachability analysis, dependency hypergraphs, and decision optimization, with a **formally verified plan checker** and a **tamper-evident audit log**.

![status](https://img.shields.io/badge/status-pre--alpha-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![offline](https://img.shields.io/badge/works-air--gapped-success)
![telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)

</div>

> **Honesty note.** This README describes the design and target behavior of DepRisk. Every feature is tagged with its status in [Feature status](#feature-status). Benchmark numbers are never hand-written: they are produced by `deprisk bench` and committed under `benchmarks/results/`. If a number is not there, it does not exist yet.

---

## Table of contents

1. [The problem](#the-problem)
2. [What DepRisk does differently](#what-deprisk-does-differently)
3. [Quick start](#quick-start)
4. [Installation](#installation)
5. [Usage](#usage)
6. [How it works (the method)](#how-it-works-the-method)
7. [Architecture](#architecture)
8. [Formal verification](#formal-verification)
9. [Tamper-evident audit log](#tamper-evident-audit-log)
10. [Air-gapped operation](#air-gapped-operation)
11. [CI/CD integration](#cicd-integration)
12. [Configuration](#configuration)
13. [Evaluation and reproducibility](#evaluation-and-reproducibility)
14. [Threat model and limitations](#threat-model-and-limitations)
15. [Feature status](#feature-status)
16. [Roadmap](#roadmap)
17. [For teams and companies](#for-teams-and-companies)
18. [Contributing](#contributing)
19. [Research and citation](#research-and-citation)
20. [License](#license)

---

## The problem

A typical mid-size project has hundreds of transitive dependencies. A scanner reports dozens or hundreds of advisories. Teams then do one of three things:

1. **Fix everything by CVSS order.** CVSS measures severity in a generic scenario, not *your* exposure. Most "critical" findings sit in code paths your application never calls.
2. **Ignore the noise.** Alert fatigue wins and real risk hides in the pile.
3. **Bump everything to latest.** This breaks builds, burns engineering time, and still gives no guarantee the result is consistent.

Three questions are left unanswered by mainstream tooling:

| Question | Why it is hard |
|---|---|
| *Is the vulnerable code reachable from my application?* | Needs call-graph analysis, not just version matching. |
| *How sure are we, and what is the downside if we are wrong?* | Risk is a distribution, not a single number. |
| *Given limited time, which set of upgrades is best, and is that set even consistent?* | Packages constrain each other in groups (hyperedges), and the best set is an optimization problem. |

DepRisk answers all three, from the terminal, offline if you need it.

## What DepRisk does differently

- **Reachability-aware.** Maps each advisory to vulnerable symbols and checks whether your code can reach them. Findings are labeled `reachable`, `possibly-reachable`, `unreachable`, or `unknown`, never silently dropped.
- **Uncertainty-driven.** Risk is modeled as a probability distribution (not a point score). Plans can optimize expected risk *and* tail risk (CVaR).
- **Decision optimization.** Remediation is solved as a constrained optimization problem: minimize residual risk under an effort budget and compatibility constraints.
- **Hypergraph model.** Multi-package constraints (for example, three packages that must move together) are first-class hyperedges, not flattened into pairwise edges.
- **Verified plans.** A small, formally proven kernel (Ada/SPARK) independently checks every plan. The optimizer is *untrusted*; the checker is *proven*.
- **Auditable.** Every decision is recorded in a hash-chained, signed log you can verify offline.
- **Air-gapped ready.** Signed offline data bundles; zero network calls by default during analysis.
- **Interoperable.** Reads CycloneDX/SPDX SBOMs and lockfiles; emits SARIF, JSON, and OpenVEX.
- **Deterministic.** Same inputs, same seed, same plan. LLM explanations are optional, local-model capable, and never influence the plan.

## Quick start

What works today (`0.1.0-alpha.1`, everything offline):

```bash
# 1. Install the .NET tool (pre-release)
dotnet tool install -g DepRisk.Cli --prerelease

# 2. Inside your project
cd my-project
dotnet restore                    # NuGet: scan reads the restore output (obj/project.assets.json)
                                  # npm: scan reads package-lock.json (npm install --package-lock-only is enough)
deprisk init                      # optional: start a signed audit log (.deprisk/)

# 3. Analyze
deprisk scan                      # the resolved dependency graph; --ecosystem nuget|npm if both are present
deprisk graph                     # its hypergraph: every requirement checked against what is installed
deprisk match --advisories NuGet.zip   # (npm: npm.zip) known vulnerabilities, from OSV data you supply
deprisk rank --advisories NuGet.zip --epss epss_scores-current.csv.gz --kev known_exploited_vulnerabilities.json   # baseline priority order
deprisk ci --advisories NuGet.zip --fail-on "kev&fixable,cvss>=9" --format sarif --out deprisk.sarif   # CI gate + code scanning
deprisk audit verify              # verify the audit log
```

Advisory data (OSV dumps), EPSS scores, and the CISA KEV list are files you download on a connected machine and pass in; DepRisk never downloads anything.

Planned (not in any release yet; see [Feature status](#feature-status)):

```bash

# Get a provably consistent fix plan within 6 engineer-hours
deprisk plan --budget 6h --out plan.json
deprisk verify plan.json          # formally checked by the SPARK kernel

# Preview or apply
deprisk apply plan.json --dry-run
deprisk apply plan.json --branch deprisk/fix-2026-10
```

Illustrative output of a planned command (format only; numbers are made up for this example):

```text
$ deprisk rank --top 5

 #  ADVISORY            PACKAGE              REACH       P(exploit)  RISK p50  RISK p95
 1  GHSA-xxxx-xxxx      lib-a 2.3.1          reachable   0.41        8.7       12.4
 2  CVE-2025-XXXXX      lib-b 1.9.0          possibly    0.18        3.1        9.8
 3  CVE-2024-XXXXX      lib-c 4.0.2          reachable   0.02        1.4        3.3
 4  CVE-2025-XXXXX      lib-d 0.8.7          unreachable 0.60        0.0        0.9
 5  GHSA-xxxx-xxxx      lib-e 5.1.0          unknown     0.07        0.8        4.1

 38 findings total | 6 reachable | 9 possibly | 17 unreachable | 6 unknown
```

## Installation

> **Pre-alpha:** only Option A (as a pre-release) and Option D work today. Options B and C describe the intended distribution and become valid when they ship (see [Feature status](#feature-status) and [Roadmap](#roadmap)). The reachability analyzer and the verification kernel do not exist yet, so the CLI is currently the only binary.

### Option A: .NET global tool

```bash
dotnet tool install -g DepRisk.Cli --prerelease
deprisk doctor        # checks the installation
```

### Option B: prebuilt binaries (planned)

Download the archive for your OS from the Releases page. Archives will include checksums and signatures.

```bash
sha256sum -c SHA256SUMS
tar -xzf deprisk-<version>-linux-x64.tar.gz
sudo install deprisk /usr/local/bin/
```

### Option C: Docker (planned)

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/codeoops-dev/deprisk:latest scan
```

### Option D: from source

Requirements today: the .NET 10 SDK. (The Rust toolchain and GNAT/GNATprove will be needed once the reachability analyzer and the SPARK kernel land.)

```bash
git clone https://github.com/codeoops-dev/deprisk.git
cd deprisk
dotnet build -c Release
dotnet test -c Release
dotnet run --project src/DepRisk.Cli -- scan path/to/your/project
```

## Usage

Commands marked *(planned)* do not exist yet; the table in [Feature status](#feature-status) is the source of truth. Output formats are per command (listed below). Everything that exists today works offline and never makes a network call. Exit codes are stable and documented below.

| Command | Purpose |
|---|---|
| `deprisk init [path]` | Create `.deprisk/` with a signing key and start the signed audit log. Never overwrites anything. |
| `deprisk scan [path]` | Read the resolved dependency graph: NuGet (`project.assets.json`, written by `dotnet restore`) or npm (`package-lock.json`, lockfileVersion 2 and 3). `--ecosystem auto\|nuget\|npm` (default: detect; a tree with both is an error that asks you to choose), `--format table\|json`, `--out`. Offline and deterministic. |
| `deprisk match [path]` | Match the resolved dependencies against local OSV advisories: `--advisories <dir\|.zip\|.json>` (required), `--ecosystem`, `--format table\|json`, `--out`, `--strict`. Offline; matching is by version only. |
| `deprisk rank [path]` | Like `match`, ordered by the baseline method: CISA KEV, then EPSS, then CVSS v3 base score. `--advisories <...>` (required), `--epss <csv[.gz]>`, `--kev <json>`, `--ecosystem`, `--format table\|json\|sarif`, `--out`, `--strict`; optionally `--symbols <file\|dir>` (with `--source`, `--analyzer`, `--entrypoints`, `--entrypoint`, `--timeout`) adds a reachability verdict to each finding without changing the order. Offline; the reference (B2) for the later model. |
| `deprisk graph [path]` | The dependency hypergraph of the resolved graph: nodes, hyperedges (one per package version that requires something, plus a project hyperedge), every requirement checked against the resolved version (violated and undecided ones are listed), statistics. NuGet and npm (for npm, requirements are resolved the way Node does it and ranges are node-semver). `--ecosystem`, `--format table\|json\|dot`, `--out`. Offline. |
| `deprisk reach [path]` | For every advisory that applies, can the vulnerable code be reached from your application (C#)? `--advisories <...>` and `--symbols <file\|dir>` (required; see [docs/symbol-maps.md](docs/symbol-maps.md)), `--source <dir>`, `--entrypoints auto\|public-api\|none`, `--entrypoint <Ns.Type.Method>`, `--analyzer <file>` (or `DEPRISK_REACH`; build it from `analyzers/reach`, it is not in the NuGet package yet), `--timeout`, `--format table\|json`, `--out`. Offline. |
| `deprisk rank --model risk` | Risk distributions by seeded Monte Carlo (`R = Reach x Exploit x Impact`): per finding mean, p50, p90, p95, cvar95, and the baseline rank for comparison. `--samples`, `--seed`, `--rank-by mean\|p50\|p90\|p95\|cvar95`, `--risk-params <file>`. Uses reachability when `--symbols` is given. The built-in parameters are **uncalibrated placeholders** and say so in every result (ADR 0015). |
| `deprisk plan` *(planned)* | Compute an optimal remediation plan under budget and constraints. |
| `deprisk verify <plan>` *(planned)* | Check a plan with the formally verified kernel. |
| `deprisk apply <plan>` *(planned)* | Apply a verified plan (manifest edits, branch, optional PR). |
| `deprisk explain <id> [path]` | Why a finding stands where it does: the baseline key that decided its place (or the risk statistic and the baseline rank), the evidence (installed where, fixed in, KEV, EPSS, CVSS), the reachability path step by step with the symbol sources, and what would change the picture. `<id>` is an advisory id or alias; `--package`, the analysis options of `rank` (`--advisories`, `--epss`, `--kev`, `--symbols`..., `--model risk`...), `--format table\|json`, `--out`. Every sentence is built from the data by a fixed template. |
| `deprisk vex [path]` | An OpenVEX 0.2.0 document, one statement per finding, for `--product <purl\|iri>` by `--author <text>` (`--role`, `--timestamp <rfc3339>`; the analysis options of `rank`). `not_affected` (justification `vulnerable_code_not_in_execute_path`) only for a finding proven unreachable under strict conditions (see below); `affected` with an action for a reachable one; everything else `under_investigation`. |
| `deprisk audit verify [path]` | Verify the integrity of the audit log (`--pubkey <file>`, `--head <hash>`). |
| `deprisk bundle create\|import\|verify` *(planned)* | Build or load signed offline data bundles. |
| `deprisk bench --cases <manifest.json>` | Compare the baselines (B1 CVSS only, B2 KEV/EPSS/CVSS, B3 reachable-only in a naive and a conservative form) with the risk model on labeled cases, with a held-out split (`--split dev\|test\|all`), a leakage guard on the EPSS and KEV dates, case-level bootstrap intervals, reachability precision/recall and unsound-`unreachable` counts, and calibration (Brier, log loss, reliability). Offline and deterministic; `--samples`, `--seed`, `--rank-by`, `--risk-params`, `--bootstrap`, `--analyzer`, `--strict`, `--format table\|json`, `--out`. Format and reading guide: [docs/benchmarks.md](docs/benchmarks.md) (ADR 0017). |
| `deprisk bench calibrate --cases <manifest.json> --out <risk-params.json>` | Fit the Reach factor of the risk model on the `dev` split (a Beta posterior per reachability label; `--prior uniform\|current`, `--min-count`, `--risk-params`) and write a complete parameters file with a provenance note. Judge it on the `test` split with `deprisk bench --split test --risk-params <file>`. Exploit and Impact are not fitted. ADR 0018. |
| `deprisk ci [path]` | One-shot CI mode: like `rank`, plus a policy gate. `--fail-on <expression>` (see below) makes it exit with code 1 when a finding matches; `--format table\|json\|sarif`, `--out`; optionally `--symbols <file\|dir>` with `--source`, `--analyzer`, `--entrypoints`, `--entrypoint`, `--timeout` (as for `reach`) to add reachability and use it in the gate. The verdict is printed on standard error so json and sarif on standard output stay clean. |
| `deprisk doctor` | Diagnose the installation. |

### When `vex` says "not affected"

A VEX statement is made for other people to rely on, so `not_affected` is the hardest status to earn. `deprisk vex` writes it only for a finding whose reachability verdict is `unreachable`, which itself requires a symbol list declared `complete`, every source file read, no unreadable reflection or call on a value of unknown type in the reachable code, and a direct dependency; `vex` then checks again that the package is a direct dependency everywhere it occurs, that no file was skipped or unreadable, and that the symbol list has provenance. If any condition fails, the statement is `under_investigation` with a note. Without `--symbols` every statement is `under_investigation`. The impact statement names the analyzer, the digest of the analyzed sources, and the digest of the symbol maps. It is a statement about a conservative call graph, not a proof (ADR 0016).

### Examples (planned commands)

These show the intended interface of commands that are not released yet.

```bash
# Be risk-averse: weight the worst 5% of outcomes
deprisk plan --budget 8h --risk-aversion 0.4 --cvar-alpha 0.95

# Forbid major-version bumps for specific packages
deprisk plan --budget 4h --pin lib-x --no-major lib-y

# Export "not affected" statements to share with customers
deprisk vex --status not_affected --out vex.json

# Reproducible run
deprisk plan --seed 42 --solver cbc --out plan.json
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, policy satisfied |
| 1 | Policy gate failed (for example, reachable finding above threshold) |
| 2 | Plan verification failed |
| 3 | Audit log integrity failure |
| 4 | Input or configuration error |
| 5 | Internal error |

## How it works (the method)

### 1. Dependency hypergraph

Ordinary dependency graphs use pairwise edges: *A depends on B*. Real constraints often involve several packages at once (a framework family that must share a version line, a plugin set that must match a host). DepRisk models these as hyperedges.

Let `P` be the set of packages and `V_p` the candidate versions of package `p`. A configuration picks exactly one version per package. A hyperedge `e = (S_e, C_e)` has a scope `S_e ⊆ P` and a set of allowed joint assignments `C_e`. A configuration is **consistent** iff every hyperedge's scope assignment lies in `C_e`.

### 2. Reachability

For each advisory, DepRisk resolves a **symbol set** (functions, methods, or modules that carry the flaw) from, in priority order:

1. explicit symbol data in the advisory (for example OSV ecosystem-specific fields),
2. a curated symbol map shipped in the data bundle,
3. symbols **mined from the upstream fix commit** (functions changed by the patch).

A Rust analyzer builds a conservative call graph from your declared entrypoints and checks whether any path reaches the symbol set. Dynamic features (reflection, dynamic dispatch, eval-like constructs) add *possible* edges marked as such. Output is one of:

`reachable` (path found) · `possibly-reachable` (path needs dynamic edges) · `unreachable` (no path in the over-approximated graph) · `unknown` (no symbol data, or unsupported construct)

`unknown` is deliberately **not** treated as safe.

### 3. Risk under uncertainty

For finding `v`, risk is the product of three uncertain quantities:

```
R_v = Reach_v × Exploit_v × Impact_v
```

- `Reach_v ~ Beta(α, β)` where parameters depend on the reachability label and analyzer precision, calibrated on the benchmark.
- `Exploit_v` is derived from EPSS and KEV membership, modeled as a calibrated Beta to represent forecast uncertainty.
- `Impact_v` comes from your asset-criticality policy (`deprisk.toml`), with optional ranges.

DepRisk samples these (seeded Monte Carlo) and reports quantiles (p50, p95) rather than a single number. This is what lets a "probably fine but catastrophic if wrong" finding outrank a "probably fine and mild" one.

### 4. Remediation as optimization

Decision variables: `x_{p,v} ∈ {0,1}` (package `p` ends at version `v`).

```
minimize     E[ Σ_v (1 − fixed_v(x)) · R_v ]  +  λ · CVaR_α( Σ_v (1 − fixed_v(x)) · R_v )

subject to   Σ_v x_{p,v} = 1                       for every package p     (one version each)
             hyperedge constraints C_e              for every hyperedge e   (consistency)
             Σ_{p,v} cost(p, v0→v) · x_{p,v} ≤ B                            (effort budget)
             policy constraints (pins, no-major, license allow-list)
```

- `cost` estimates effort from semver distance and, when API-diff data is available, from **whether your code uses the changed API** (a breaking change you never touch is cheap).
- CVaR is linearized with the Rockafellar–Uryasev formulation over Monte Carlo scenarios, so the whole problem is a mixed-integer linear program solvable with open-source solvers (default: CBC/HiGHS).
- Setting `--risk-aversion 0` recovers pure expected-risk minimization.

### 5. Safe application

`apply` edits manifests/lockfiles only after the kernel accepts the plan, creates a branch, and (optionally) runs your configured build and test command in a sandbox before proposing a PR. Failed validation rolls back and is logged.

## Architecture

```mermaid
flowchart LR
    subgraph Inputs
      L[Lockfiles / SBOM]
      S[Source code]
      D[Signed data bundle<br/>OSV · EPSS · KEV · symbol maps]
    end

    subgraph Core["DepRisk CLI (C# / .NET)"]
      I[Ingest + Hypergraph builder]
      R[Risk model<br/>Monte Carlo]
      O[Optimizer<br/>MILP + CVaR]
      A[Apply + Policy + CI]
      X[Explain<br/>optional local LLM]
    end

    RA[(Reachability analyzer<br/>Rust)]
    K[(Verification kernel<br/>Ada/SPARK)]
    AL[(Audit log<br/>hash chain + ECDSA P-256)]
    ST[(Local store<br/>SQLite)]

    L --> I
    D --> I
    S --> RA
    I --> RA
    RA --> R
    I --> R
    R --> O
    O -->|plan.json| K
    K -->|accepted plan| A
    R --> X
    I --> ST
    Core --> AL
    K --> AL
```

**Design decisions**

| Decision | Rationale |
|---|---|
| CLI-first, no server | Zero setup, easy to script, easy to run in CI and air-gapped hosts. |
| C# core | Fast to evolve; strong typing for the model and optimizer glue. |
| Rust analyzer | Performance and memory safety for parsing untrusted source at scale. |
| SPARK kernel | Small trusted base with machine-checked proofs; keeps the optimizer out of the trust boundary. |
| SQLite local store | No database to install. A PostgreSQL backend for team/server mode is on the [roadmap](#roadmap) and the storage layer is behind an interface. |
| No code execution of scanned projects | Static analysis only. Build/test execution happens only in `apply --validate`, in an explicit sandbox. |

**Repository layout**

```text
deprisk/
├── src/
│   ├── DepRisk.Cli/            # commands, config, output formats
│   ├── DepRisk.Core/           # hypergraph, risk model, optimizer, policy
│   ├── DepRisk.Audit/          # hash-chained signed log
│   └── DepRisk.Data/           # bundle format, advisory ingestion
├── analyzers/
│   └── reach/                  # Rust reachability analyzer
├── kernel/
│   └── spark/                  # Ada/SPARK plan checker + proofs
├── benchmarks/
│   ├── datasets/               # pinned repo snapshots + ground truth manifests
│   └── results/                # generated by `deprisk bench`
├── docs/
│   ├── adr/                    # architecture decision records
│   ├── method.md               # full mathematical specification
│   └── threat-model.md
├── paper/                      # preprint sources and reproducibility artifacts
├── tests/
├── deprisk.toml.example
└── Makefile
```

## Formal verification

The optimizer (MILP + sampling) is complex and floating-point heavy, so it is **not** trusted. Instead, `deprisk verify` runs a small kernel written in **Ada/SPARK** and proven with GNATprove.

The kernel takes the hypergraph, the current configuration, the plan, and the budget as input. If it returns `ACCEPT`, the following are proven properties of the code:

| Property | Meaning |
|---|---|
| **P1: Uniqueness** | Every package ends with exactly one version. |
| **P2: Consistency** | Every hyperedge constraint is satisfied by the resulting configuration. |
| **P3: Budget** | Total plan cost does not exceed the budget. |
| **P4: Policy** | Pins, no-major rules, and allow-lists are respected. |
| **P5: Fix claims** | Every advisory the plan claims to fix is actually outside its affected range after the plan. |
| **P6: Absence of runtime errors** | No overflow, out-of-bounds, or uninitialized reads (SPARK AoRTE). |

Design choices that keep the proofs tractable: scaled-integer arithmetic (no floating point in the kernel), bounded collections, and a deliberately small input format. Proof status is reproducible with `make prove`; the CI pipeline fails if any verification condition is unproven.

> What is *not* proven: that the plan is *optimal* (that is the optimizer's job and is evaluated empirically), or that reachability labels are correct (see [limitations](#threat-model-and-limitations)).

## Tamper-evident audit log

Every command that reads sensitive state or changes something writes an entry:

| Field | Content |
|---|---|
| `seq`, `timestamp` | Monotonic sequence number and UTC time |
| `actor`, `host`, `cwd` | OS user, machine, working directory |
| `git_commit` | Repository state at the time |
| `command`, `args` | What was run |
| `inputs_digest`, `outputs_digest` | SHA-256 over inputs and results |
| `changes` | Structured diff, `from → to` (for example `lib-a 2.3.1 → 2.5.0`) |
| `prev_hash` | Hash of the previous entry |
| `signature` | ECDSA (P-256, SHA-256) signature over the entry, Base64 |

Entries form a hash chain, and the format is specified precisely in [`docs/audit-log.md`](docs/audit-log.md) (RFC 8785 canonical JSON), so anyone can re-implement verification. Anyone with the public key can run:

```bash
deprisk audit verify --pubkey auditor.pub
```

Editing, deleting, inserting, or reordering entries is detected. A log alone cannot show that entries were cut off its **end**, so pin the head: store the `head:` hash that `audit verify` prints somewhere you trust (a ticket, a signed release, another machine) and check it later with `deprisk audit verify --head <hash>`. Keys are generated locally by `init`; the private key stays in `.deprisk/audit.key` (owner-only permissions where the OS supports it, excluded from Git by `.deprisk/.gitignore`). Merkle checkpoints and a transparency-log style workflow are on the roadmap.

## Air-gapped operation

DepRisk makes **no network calls** during `scan`, `reach`, `rank`, `plan`, `verify`, or `audit`. Fresh data enters through signed bundles:

```bash
# On a connected machine
deprisk bundle create --sources osv,epss,kev,symbols --out deprisk-bundle-2026-10-27.tar
deprisk bundle sign   deprisk-bundle-2026-10-27.tar --key release.key

# Transfer via approved media, then on the isolated machine
deprisk bundle verify deprisk-bundle-2026-10-27.tar --pubkey release.pub
deprisk bundle import deprisk-bundle-2026-10-27.tar
```

Bundles are versioned and timestamped; DepRisk warns when your data is older than the configured freshness window. No telemetry is collected, ever.

## CI/CD integration

`deprisk ci` runs the whole analysis (scan, match, rank) and then evaluates a **policy gate**. It is non-interactive, deterministic, offline (you supply the data files), writes SARIF for code-scanning platforms, and returns the documented exit codes: **0** the gate passed (or no gate was set), **1** the gate failed, **4** bad input (including an invalid `--fail-on`).

### Policy gate: `--fail-on`

Clauses separated by `,` (any clause may fail the gate); each clause is terms joined by `&` (all must hold for the same finding).

| Term | Holds when |
|---|---|
| `any` | there is any finding |
| `kev` | the finding is listed in the CISA KEV catalog |
| `ransomware` | it is in KEV with known ransomware use |
| `direct` | the vulnerable package is a direct dependency somewhere |
| `fixable` | the advisory lists a fixed version above the installed one |
| `cvss>=N`, `cvss>N` | the CVSS v3 base score (0 to 10) compares so |
| `epss>=P`, `epss>P` | the EPSS probability (0 to 1) compares so |
| `severity>=LEVEL` | the database rating is at least `low`, `moderate` (or `medium`), `high`, `critical` |
| `reachable` | the reachability verdict is `reachable` (needs `--symbols`) |
| `possibly-reachable` | the verdict is `possibly-reachable` (needs `--symbols`) |
| `reach-unknown` | the verdict is `unknown` (needs `--symbols`) |
| `unreachable` | the verdict is `unreachable` (needs `--symbols`) |
| `not-unreachable` | the verdict is anything but `unreachable`: `reachable`, `possibly-reachable`, or `unknown`. The safe way to gate: only what is *proven* unreachable is let through (needs `--symbols`) |

A term about a signal that is not available for a finding is false for it (never "zero"). Examples: `kev` · `kev&fixable,cvss>=9` · `direct&severity>=high`. The reachability terms need `--symbols` (and the analyzer); without it the command stops with an input error instead of letting them silently match nothing, and a finding that was not analyzed matches none of them. Probability quantiles do not exist yet and are rejected with an error, not ignored. Reachability never changes the order of `rank`; it is shown and can be used in the gate. A typical gate: `kev&fixable,cvss>=9&not-unreachable`.

### SARIF levels

`error` if the finding is in KEV, or its CVSS rating (else the database rating) is critical or high; `warning` for medium or moderate and for unknown ratings; `note` for low. Rules carry GitHub's `security-severity` (the CVSS base score) when known. Results point at the project files that use the package.

### GitHub Actions example

```yaml
# .github/workflows/deprisk.yml
name: deprisk
on: [pull_request]
permissions:
  contents: read
  security-events: write      # to upload SARIF
jobs:
  deprisk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 10.0.x
      - run: dotnet restore    # deprisk reads obj/project.assets.json
      - run: dotnet tool install -g DepRisk.Cli --version 0.1.0-alpha.1   # pin the version
      - name: Fetch advisory data (check the URLs; see docs/adr/0006 and 0007)
        run: |
          curl -fsSL -o NuGet.zip https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip
          curl -fsSL -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
          curl -fsSL -o epss.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
      - name: DepRisk gate
        run: >
          deprisk ci --advisories NuGet.zip --epss epss.csv.gz --kev kev.json
          --fail-on "kev&fixable,cvss>=9" --format sarif --out deprisk.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()           # upload findings even when the gate fails
        with:
          sarif_file: deprisk.sarif
```

The advisory, EPSS, and KEV files are third-party data fetched by *your* workflow; DepRisk itself never downloads anything. Their digests and published dates are recorded in the output. A GitHub Action wrapper is on the roadmap.

## Configuration

`deprisk.toml`:

```toml
[project]
name = "my-service"
entrypoints = ["src/Api/Program.cs", "src/Worker/Main.cs"]
ecosystems = ["nuget", "npm"]

[assets]
# Impact tiers feed the risk model (ranges express uncertainty)
default_impact = [3.0, 6.0]
[assets.overrides]
"src/Payments/**" = [8.0, 10.0]

[risk]
samples = 5000
seed = 42
cvar_alpha = 0.95
risk_aversion = 0.3

[plan]
budget = "6h"
solver = "highs"
no_major = ["lib-y"]
pin = ["lib-x"]

[policy]
fail_on = "reachable:p95>=7"
license_allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]
data_freshness_days = 14

[apply]
validate_cmd = "dotnet test"
sandbox = true

[audit]
key = ".deprisk/audit.key"
```

## Evaluation and reproducibility

Claims should be falsifiable. DepRisk ships its own evaluation harness.

**Baselines compared**

| Baseline | Description |
|---|---|
| B1 | CVSS-only ordering |
| B2 | CVSS + EPSS/KEV |
| B3 | Reachable-only filtering (no uncertainty, no optimization) |
| B4 | "Upgrade everything to latest" |
| **DepRisk** | Full pipeline |

**Metrics**

| Metric | What it tells you |
|---|---|
| Residual expected risk vs. effort (Pareto curve) | Quality of prioritization under a budget |
| Alert reduction with no missed known-exploited findings | Noise removed without losing real risk |
| Reachability precision/recall on labeled cases | Analyzer quality |
| Post-plan build/test pass rate | Whether "safe" remediation is actually safe |
| Plan verification time | Practical cost of formal checking |
| Calibration of risk quantiles | Whether stated uncertainty is honest |

**Reproduce**

```bash
make bench                      # full suite, pinned datasets, fixed seeds
deprisk bench --suite quick     # smoke test, minutes
```

Datasets are pinned by commit hash with ground-truth manifests (known-exploited advisories, historical fix commits). Results land in `benchmarks/results/` as machine-readable files plus generated plots. **No result is reported unless it can be regenerated by these commands.**

**Format and reading guide:** [docs/benchmarks.md](docs/benchmarks.md). B3 is run in two forms: *naive* (keep only findings called reachable) and *conservative* (drop only those called unreachable), so the comparison is fair; B4 and the Pareto and post-plan metrics wait for the planner and the kernel, and every result lists them as not evaluated.

> Results: *not yet generated.* The harness exists and is tested on a synthetic dataset whose numbers are not evidence. This section will be filled from `benchmarks/results/` when a real dataset has been run.

## Threat model and limitations

DepRisk analyzes untrusted code and handles security-relevant decisions, so its own limits are stated plainly.

**Security posture**

- Static analysis only; scanned projects are never executed by `scan`/`reach`/`rank`/`plan`.
- Parsers run in the memory-safe analyzer process; `apply --validate` runs project commands only inside a sandbox you configure.
- Data bundles are signature-verified before import; unsigned bundles are rejected unless `--insecure-allow-unsigned` is passed (and this is logged).
- No telemetry, no phone-home.
- See [`docs/threat-model.md`](docs/threat-model.md) for assets, adversaries, and mitigations.

**Known limitations**

| Limitation | Effect | Handling |
|---|---|---|
| Reflection, dynamic loading, eval-like code | Call graph may miss or over-approximate paths | Marked `possibly-reachable`/`unknown`, never silently "safe" |
| Missing symbol data for an advisory | Cannot decide reachability | Labeled `unknown`; counted as risk |
| EPSS/KEV are forecasts and incomplete | Exploit probability is uncertain | Modeled as distributions |
| Effort/cost estimates are heuristic | Plans may over/under-budget | Budget is a model input; calibrate with `deprisk bench` |
| Ecosystem coverage | Initial release covers a subset | See [Feature status](#feature-status) |
| Kernel proves consistency, not optimality | A verified plan may be suboptimal | Optimality evaluated empirically |

Found a security issue in DepRisk itself? See [`SECURITY.md`](SECURITY.md) for private disclosure.

## Feature status

Legend: ✅ implemented · 🚧 in progress · 🗺️ planned

| Area | Feature | Status |
|---|---|---|
| Ingest | NuGet restore graph (`project.assets.json`) via `deprisk scan` | ✅ |
| Ingest | NuGet lockfiles (`packages.lock.json`) | 🗺️ |
| Ingest | npm lockfiles (`package-lock.json`, lockfileVersion 2 and 3, workspaces, aliases) via `deprisk scan`; `rank` and `ci` work for npm too | ✅ |
| Match | Advisory matching: OSV records (dir, .zip, .json), NuGet and npm (SemVer) version ranges, offline, via `deprisk match` | ✅ |
| Rank | Baseline ranking (KEV, EPSS, CVSS v3 base score; no reachability or uncertainty) via `deprisk rank` | ✅ |
| Rank | CVSS v4.0 scoring | 🗺️ |
| Ingest | CycloneDX / SPDX SBOM | 🗺️ |
| Model | Dependency hypergraph of the resolved graph (NuGet; npm with Node-style path resolution and node-semver ranges), requirement checks, DOT/JSON export via `deprisk graph` | ✅ |
| Model | Hypergraph with candidate versions and allowed tuples (for the optimizer) | 🗺️ |
| Analysis | Reachability: C# analyzer (`analyzers/reach`: standalone process with a JSON protocol, conservative call graph, labels reachable / possibly-reachable / unreachable / unknown; build from source; not yet wired into the CLI) | 🚧 |
| Analysis | `deprisk reach` with symbol maps ([format](docs/symbol-maps.md)); needs the analyzer built from source | 🚧 |
| Analysis | Reachability labels in `rank` and `ci` output (JSON, table, SARIF property) with `--symbols`; shown, not used for the order | 🚧 |
| Analysis | Reachability: JS/TS | 🗺️ |
| Analysis | Symbol mining from fix commits | 🗺️ |
| Risk | Uncertainty model: `rank --model risk` gives each finding a risk distribution (seeded Monte Carlo over Reach x Exploit x Impact; mean, p50, p90, p95, cvar95) next to its baseline rank. The parameters are **uncalibrated placeholders** (shown in every result); calibration on labeled cases is still to do | 🚧 |
| Eval | `deprisk bench`: labeled-case benchmark harness with baselines B1/B2/B3, a held-out split, a temporal leakage guard, reachability against ground truth, and calibration measures (ADR 0017). Only a synthetic smoke dataset exists; **no benchmark result has been produced yet** | 🚧 |
| Plan | MILP optimizer with CVaR | 🗺️ |
| Verify | SPARK kernel (P1–P6) | 🗺️ |
| Audit | Hash-chained signed log, `init`, `audit verify` (head pinning included) | ✅ |
| Audit | Merkle checkpoints and external anchoring | 🗺️ |
| Offline | Signed bundles | 🗺️ |
| Output | SARIF 2.1.0 and JSON for ranked findings (`rank`, `ci`) | ✅ |
| Output | OpenVEX 0.2.0 export via `deprisk vex` (`not_affected` only under strict conditions, ADR 0016) | 🚧 |
| Output | `deprisk explain`: evidence, reachability path, risk, and what would change it, as text or JSON | 🚧 |
| CI | `deprisk ci` + policy gate (`kev`, `ransomware`, `direct`, `fixable`, `cvss`, `epss`, `severity`) | ✅ |
| CI | Reachability terms in the policy gate (`reachable`, `possibly-reachable`, `reach-unknown`, `unreachable`, `not-unreachable`); needs the analyzer built from source | 🚧 |
| CI | GitHub Action wrapper | 🗺️ |
| Explain | Deterministic evidence report | 🗺️ |
| Explain | Optional local-LLM narrative | 🗺️ |

*(Update this table as features land; it is the source of truth for what works today. Shipped in `0.1.0-alpha.1`: every row marked ✅.)*

## Roadmap

- **v0.1** CLI skeleton, NuGet + npm ingest, hypergraph, advisory matching, risk ranking (CVSS+EPSS+KEV baseline), audit log, `ci` policy gate, SARIF. First pre-release: `0.1.0-alpha.1`.
- **v0.2** Reachability (C#, JS/TS), uncertainty model, `explain`, OpenVEX export. Done in the repository, not yet in a release: C# reachability, the uncertainty model with placeholder parameters, `explain`, `vex`. The benchmark harness (`deprisk bench`, ADR 0017) is also in the repository, without a real dataset. Still to do: the JS/TS analyzer, shipping the analyzer with the tool, real symbol data, and a real labeled dataset. `deprisk bench calibrate` (ADR 0018) can fit the Reach factor from such a dataset; Exploit and Impact are still placeholders.
- **v0.3** Optimizer (MILP + CVaR), plan format, `plan`/`apply --dry-run`.
- **v0.4** SPARK kernel and proofs, `verify`, first published benchmark results (the harness itself is already in the repository, see v0.2).
- **v0.5** Signed offline bundles, GitHub Action (the `ci` command and SARIF output already ship with v0.1).
- **v1.0** Stable plan/audit formats, documented exit codes and schemas, preprint.
- **Later** More ecosystems (Cargo, PyPI, Maven, Go), PostgreSQL team mode, transparency-log checkpoints, richer API-diff-based cost model.

## For teams and companies

If you evaluate tooling for a security or platform team, here is what to check:

| You care about | What to look at |
|---|---|
| Noise reduction | `deprisk bench` alert-reduction metric and `explain` output for suppressed findings |
| Trust in automation | The proven kernel and its published properties (P1–P6) |
| Compliance and audit | Signed audit log, OpenVEX export, SARIF in your existing pipeline |
| Restricted networks | Air-gapped workflow and signed bundles |
| Data privacy | No telemetry, no source code leaves the machine |
| Adoption cost | Single CLI, no server or database to run, standard exit codes |

**Pilot it in a day:** run `deprisk scan && deprisk reach && deprisk rank` on one service, compare the top 10 against your current process, and open an issue with what it got right or wrong. Negative results are valuable and will be credited.

## Contributing

Contributions are welcome, especially:

- ecosystem parsers and reachability support for new languages,
- curated vulnerable-symbol maps,
- benchmark datasets with ground truth,
- proof engineering and review of the SPARK kernel,
- real-world false-positive/false-negative reports.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Please open an issue before large changes. Architecture decisions are recorded in [`docs/adr/`](docs/adr/).

## Research and citation

DepRisk is developed alongside academic research on risk-aware, uncertainty-driven remediation of dependency vulnerabilities. Open research questions the project is designed to test:

1. Does modeling uncertainty (and tail risk) produce better remediation plans than point-score ranking at equal effort?
2. How much does hyperedge-aware consistency modeling reduce failed or inconsistent upgrades versus pairwise models?
3. How well do symbols mined from fix commits approximate curated vulnerable-function data for reachability?
4. What is the practical cost of verifying plans with a proven kernel?

If you use DepRisk in academic work, please cite it (see [`CITATION.cff`](CITATION.cff)). A preprint will be linked here when available.

**Author:** Jahed Kabiri, Tabriz, Iran. Issues and discussions on this repository are the best way to reach the project.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

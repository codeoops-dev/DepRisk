# Roadmap: what is done and what remains

This page is the working list behind the short [Roadmap](../README.md#roadmap) in the README. It says what each phase still needs, in the order it is meant to be done, and which items need data or a decision from the maintainer rather than code. Release versions follow the phases: pre-release `-alpha.N` until a phase is complete, and no new release is cut until the work below it is done.

## How the phases are kept compatible

Later versions extend; they do not change what earlier ones accept or produce.

- A new option, field, subcommand or output is **added**. An input that was accepted keeps its meaning; an output field keeps its name, type and meaning.
- When two commands disagree, the more accepting rule becomes the shared one (as with whole-number options in S21), so no command line that worked stops working.
- A breaking change to a file format needs a new `schemaVersion` and a note in the ADR; until then a format only grows.
- Code that must serve both old and new callers keeps the old entry point and adds an overload or an optional parameter (as `AnalysisArgs.RequireAdvisories` did).

## v0.2: reachability (shipped as `0.2.0-alpha.1`, completed here before v0.3 starts)

Done: C# and JS/TS reachability, the uncertainty model, `explain`, signed OpenVEX, the benchmark harness, the bundled analyzer, `symbols template` (ADR 0024), `symbols check` (ADR 0025), the checks that stop an incomplete list or a contradictory answer from becoming `unreachable` (ADR 0023, ADR 0026), one shared way to read option values and whole numbers in every command (S20, S21), and one set of risk-model options for `rank`, `ci`, `explain`, `vex` and `bench` (S21).

### Items left over from v0.1 and v0.2 (found by reading the README Feature status table against the code)

These were planned, listed in the README, and not built. They are finished before v0.3 where they do not need a decision, because v0.3 (budgets, pins, history) leans on some of them.

| Item | Needs | Notes |
|---|---|---|
| NuGet `packages.lock.json` ingest, `package-lock.json` lockfileVersion 1 | Code only | README Ingest rows |
| CVSS v4.0 scoring | Code only | README Rank row; ADR 0007 names it as a follow-up |
| CycloneDX and SPDX SBOM ingest | Code only | README Ingest row; components with a package URL for NuGet and npm |
| `doctor --format json`, a different key location for `init`, streaming `audit verify` for large logs | Code only | Small items listed with the v0.1 slices |
| README: the Feature status table lists `explain` twice (in progress and planned) | Docs only | Merge the rows |
| `deprisk.toml` configuration | A decision | See the options below |
| Local store (ADR 0002), baseline and new-findings-only gating, data freshness policy | A decision | Needs a storage dependency; see below |
| Passphrase-protected private key for the audit log | A decision | Security-sensitive: how the passphrase is supplied non-interactively in CI |
| Symbol mining from fix commits | A decision | Analysis is offline; mining needs a separate, network-using tool and its own trust model |
| Merkle checkpoints and anchoring audit heads outside the machine | Later | README "Later" |

### Engineering that does not wait on v0.3

| Item | Needs | Notes |
|---|---|---|
| Pinned Rust toolchain for reproducible analyzer builds | Code and CI | ADR 0022 records that `stable` is used today; pin with `rust-toolchain.toml` and use it in every workflow |
| Analyzers for `linux-musl-x64` and `win-arm64` | Code and CI runners | Build matrix, runtime identifier mapping in the locator, packaging; verified only by CI |
| Code signing and a run-time checksum check of the bundled analyzer | A decision | Options below |
| Sigstore (keyless) signing of VEX documents | A trust decision | |
| JSON output for `symbols check` | Only if a consumer needs it | Would come with its own schema |
| Reachable and unknown answers: path consistency | Code, careful | ADR 0026 limit: needs the analyzer's own rules before a check can be added |
| Micro-averaged metrics view, provenance check in the leakage guard, hierarchical Reach fit, correlated sampling, per-asset impact | Research design | From the benchmark and uncertainty ADRs; per-asset impact needs the configuration file |

### Needs the maintainer's data

| Item | Notes |
|---|---|
| Real symbol maps for real npm and NuGet advisories | Start from `deprisk symbols template`, keep them honest with `deprisk symbols check`. This is the bottleneck of the research claim |
| First real labeled benchmark dataset, then calibration and fitting of Exploit and Impact | Goes under `benchmarks/datasets/` with the first dataset |

### Decisions the leftover items wait on (options)

**Configuration file (`deprisk.toml`).** The product projects have no package dependencies today.
(a) A TOML library: least code, one dependency in a security tool. (b) A small hand-written parser for the subset DepRisk needs: no dependency, more code to test, and a bug there is ours. (c) JSON with the same keys, validated by a schema like every other file: no dependency and consistent with the rest of the formats, but less pleasant to write by hand and has no comments. A decision here also settles the policy file that v0.3 needs (pins, forbidden versions, no-major rules).

**Local store (ADR 0002).** (a) SQLite through a library: the ADR's own choice, brings a native component per platform. (b) Plain files under `.deprisk/` (JSON lines, atomically replaced): no dependency, enough for "findings seen before" and a freshness date, not for queries. The new-findings-only gate and freshness policy only need (b) to start; team mode needs (a).

**Run-time checksum and signing of the bundled analyzer.** (a) Embed the expected SHA-256 of each analyzer in the CLI assembly at pack time and check before every run: the hashes travel inside the signed NuGet package, so replacing only the binary is detected. (b) A manifest file beside the binaries: simpler, but an attacker who can replace the binary can replace the manifest. (c) Code signing the binaries per platform: stronger, costs certificates and a signing step per platform. (a) is the proposal; (c) is a separate decision about money and keys.

## v0.3: optimizer, plan format, `plan` and `apply --dry-run`

Not started. The design is in [`docs/method.md`](method.md), sections 5 to 7: binary choices `x(p,v)` (one version per package), hyperedge consistency through binaries `z(e,t)` over allowed tuples, an effort budget, pins and forbidden pairs, and a scenario-based CVaR objective linearized with `η` and `u(s)`. The optimizer is not trusted: the plan is checked by the kernel (v0.4), which is why the plan must be integer-based and self-describing.

Proposed order, each step behind an ADR:

1. **ADR: where candidate versions come from.** The central open question. The model needs, for each package, the candidate versions and the dependency requirements of each, and analysis is offline. Options: (a) only versions DepRisk already knows (installed, and the fixed versions in the advisory data), with requirements for those unknown, so tuples cannot be checked: weak, because a plan could break a hyperedge; (b) a catalog file of package versions and their requirements, produced by a separate step that may use the network and consumed offline, which fits the signed offline bundles of v0.5; (c) read what the local package caches already hold: offline, but only for versions already downloaded.
2. **ADR: optimizer architecture and solver.** (a) A separate process with a JSON protocol, like the reachability analyzer (ADR 0012, ADR 0022): the untrusted boundary is explicit, the solver is swappable behind the protocol, no native library is loaded into the .NET process, and packaging reuses the analyzer's platform matrix; the cost is one more binary per platform. (b) An in-process .NET binding to a native solver (HiGHS, OR-Tools): simplest to call, strongest solvers, but a heavy native dependency in a project with none, per-platform natives and a larger in-process attack surface. (c) An external solver executable fed LP files: small, but an install burden and version drift. (d) Our own exact solver: no dependency, but it means writing a MILP solver. Which Rust or native solver to start with is to be checked by building and benchmarking, not assumed. Whatever is chosen, a solver-free baseline (greedy within the budget) comes first so there is always something to compare against.
3. **ADR: `plan.v1` and the policy file.** Costs as scaled integers (the kernel is integer-only); only changed packages as `from -> to`; claimed fixed advisories; digests of the hypergraph, advisories and policy; seed, scenario count, solver identity and version; `schemaVersion`. The policy file format follows the configuration decision above.
4. **Effort model.** `base(change class)` table and `use(p, v0 -> v)` default by change class, as in method.md section 5, with the parameters declared uncalibrated, as the risk parameters are.
5. A plan data model and the baseline plan, then the MILP and CVaR objective behind the same interface, then `plan` and `apply --dry-run` with audit entries.

## v0.4 to v1.0

As in the README: the SPARK kernel and `verify` (v0.4), signed offline bundles and the GitHub Action (v0.5), stable formats and the preprint (v1.0). Not started.

## Rules that stay true in every phase

Offline analysis, no execution of scanned code, every command audited, every output deterministic and schema-validated, and no verdict quieter than the evidence for it.

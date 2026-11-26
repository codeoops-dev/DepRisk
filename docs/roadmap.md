# Roadmap: what is done and what remains

This page is the working list behind the short [Roadmap](../README.md#roadmap) in the README. It says what each phase still needs, in the order it is done, and which items wait on data from the maintainer. Release versions follow the phases: pre-release `-alpha.N` until a phase is complete, and no new release is cut until the work below it is done.

## How the phases are kept compatible

Later versions extend; they do not change what earlier ones accept or produce.

- A new option, field, subcommand or output is **added**. An input that was accepted keeps its meaning; an output field keeps its name, type and meaning.
- When two commands disagree, the more accepting rule becomes the shared one (as with whole-number options), so no command line that worked stops working.
- A breaking change to a file format needs a new `schemaVersion` and a note in the ADR; until then a format only grows.
- Code that must serve both old and new callers keeps the old entry point and adds an overload or an optional parameter.
- Documentation moves with the code: every change sweeps the README (status marks, present-tense sentences, Usage table, `--help`), and tests fail when the command list, the status legend, links or ADR references drift.

## v0.2: two milestones

1. **v0.2 code-complete** (this page, below): everything in the tables that needs no real data. The next release (`0.2.0-alpha.2`) is cut only after this.
2. **v0.2 research-complete**: real symbol maps, a first labeled dataset, a first benchmark result, calibrated parameters. This depends on the maintainer's data and is published with v0.4 ("first published benchmark results" in the README roadmap); it does not block v0.3.

Done: C# and JS/TS reachability, the uncertainty model, `explain`, signed OpenVEX, the benchmark harness, the bundled analyzer, `symbols template` (ADR 0024), `symbols check` (ADR 0025), the checks that stop an incomplete list or a contradictory answer from becoming `unreachable` (ADR 0023, ADR 0026), one way to read option values and whole numbers in every command, one set of risk-model options for `rank`, `ci`, `explain`, `vex` and `bench`, NuGet `packages.lock.json` and npm lockfileVersion 1 ingest (ADR 0027), CVSS v4.0 base scoring (ADR 0028), CycloneDX and SPDX SBOM ingest (ADR 0029), the audit key passphrase and key location, `doctor --format json`, streaming `audit verify` (ADR 0030), a pinned Rust toolchain for every workflow (ADR 0031), a build cache for CI that a release never uses (ADR 0032). A periodic chore stays: bump the pin in `analyzers/reach/rust-toolchain.toml` on purpose when the compiler has a security fix or a lint worth having.

### Order of the remaining v0.2 work

Each line is one slice; the order follows the dependencies (docs first, then inputs, then distribution, then the pieces v0.3 leans on).

| Slice | Work | Needs |
|---|---|---|
| S22 | Documentation sweep: the README status legend with the experimental mark, labels on design-only sections, the stale sentences, the `ci --help` text, the contributor checklist, and the documentation consistency tests | Code (small) and docs |
| S23 | NuGet `packages.lock.json` and npm `package-lock.json` lockfileVersion 1 ingest | Code |
| S24 | CVSS v4.0 scoring | Code |
| S25 | CycloneDX and SPDX SBOM ingest (components with a package URL for NuGet and npm) | Code |
| S26 | Small v0.1 items: `doctor --format json`, a key location for `init`, streaming `audit verify`; passphrase-protected audit key | Code |
| S27 | Pinned Rust toolchain (`rust-toolchain.toml`, used by every workflow) | Code and CI |
| S28 | Analyzers for `linux-musl-x64` and `win-arm64` (build matrix, runtime identifier mapping, packaging) | Code and CI runners; verified only by CI |
| S29 | Run-time checksum of the bundled analyzer | Code |
| S30 | `deprisk.toml` configuration (strict TOML subset) | Code |
| S31 | Local store under `.deprisk/`, gate on new findings only, data freshness policy | Code |
| S32 | Analyzer answers: path consistency (ADR 0026 limit) | Code, careful |
| S33 | `deprisk symbols mine` from a local clone (the last v0.2 slice) | Code and a trust boundary decision for running `git` |

Items that wait for real data and are not scheduled until it exists: the micro-averaged metrics view and the provenance check in the leakage guard (bench polish), the hierarchical Reach fit, correlated sampling, risk quantiles as gate terms (only with calibrated parameters), and per-asset impact (after S30).

### Needs the maintainer's data

| Item | Notes |
|---|---|
| Real symbol maps for real npm and NuGet advisories | Start from `deprisk symbols template`, keep them honest with `deprisk symbols check`. This is the bottleneck of the research claim |
| First real labeled benchmark dataset, then calibration and fitting of Exploit and Impact | Goes under `benchmarks/datasets/` with the first dataset |

## Decisions taken (2026-11-23)

| Subject | Decision | Why and conditions |
|---|---|---|
| Status marks in the README | Four marks: ✅ built and documented, 🧪 built but not validated on real data, 🚧 unfinished code, 🗺️ planned | Honest about both progress and evidence; no accuracy figure appears until a real benchmark has produced one |
| Design-only README sections | Kept and labeled *(planned)*; commands and files that do not exist are not shown as if they did | The vision stays visible without overstating what is built |
| Documentation drift | A sweep in every slice (CONTRIBUTING checklist) and consistency tests in the normal test run | A forgotten README becomes a failing build |
| Configuration | `deprisk.toml`, a strict TOML subset read by DepRisk itself: no dependency, anything outside the subset is an error | The product projects have no package dependencies today, which is part of the trust story |
| Local store | Plain files under `.deprisk/` first behind the storage interface; SQLite and PostgreSQL later as further implementations of it | Enough for "seen before" and freshness; adds no dependency |
| Symbol mining | `deprisk symbols mine` from a clone the user provides, offline; its drafts stay `complete: null` and need a person to decide | Same rule as `symbols template`: a machine never declares a list complete. Running `git` against a clone needs its own explicit trust-boundary note first |
| Risk quantiles in the gate | Only with a calibrated parameters file; otherwise an input error | A build must never fail on a placeholder number |
| Run-time checksum of the analyzer | The SHA-256 of each bundled analyzer is embedded in the CLI assembly at pack time and checked before every run; a mismatch refuses to run (exit code 3). A binary chosen with `--analyzer` is the user's own choice and is not checked | The hashes travel inside the signed NuGet package, so replacing only the binary is detected. Code signing of the binaries is a separate decision about certificates and money, needed before a release candidate |
| Audit key | Optional passphrase through encrypted PKCS#8 (built into .NET), read from an environment variable or a file, never from the command line; a key without a passphrase keeps working | Additive and non-interactive, so it works in CI |
| VEX signing | The key-based DSSE signing stays; no keyless signing (it needs the network); offline verification of Sigstore bundles may be added later | Keeps the offline guarantee |
| Candidate versions for plans (v0.3) | A catalog file of package versions and their requirements, produced by a separate step that may use the network and read offline by analysis. A local package cache may be one producer of the catalog, not the source | Plans must stay provably consistent with the dependency constraints; data DepRisk already has is not enough |
| Optimizer (v0.3) | A separate process with a JSON protocol, like the reachability analyzer; a solver-free baseline (greedy within the budget) comes first | The untrusted-optimizer boundary stays explicit and the solver stays swappable. The concrete solver is chosen by building and benchmarking, not assumed |
| `plan.v1`, policy file, effort model (v0.3) | As in `docs/method.md` sections 5 to 7: integer costs, only changed packages as `from -> to`, claimed fixed advisories, digests of inputs, seed and solver identity, `schemaVersion`; the policy file uses the configuration format; effort parameters declared uncalibrated | One ADR each, written before the code |

## v0.3: optimizer, plan format, `plan` and `apply --dry-run`

Not started. Starts after v0.2 code-complete. The design is in [`docs/method.md`](method.md), sections 5 to 7. Order, each step behind an ADR:

1. **ADR: the catalog of candidate versions** (format, who produces it, how it is signed and consumed offline).
2. **ADR: the optimizer process and its protocol**, then the solver-free baseline plan so the verifier and the benchmark have something to compare against.
3. **ADR: `plan.v1` and the policy file.**
4. **ADR: the effort model** (`base(change class)` table and the default for `use`), parameters uncalibrated.
5. The MILP and CVaR objective behind the same protocol, then `plan` and `apply --dry-run` with audit entries.

## v0.4 to v1.0

As in the README: the SPARK kernel and `verify` (v0.4), signed offline bundles and the GitHub Action (v0.5), stable formats and the preprint (v1.0). Not started.

## Rules that stay true in every phase

Offline analysis, no execution of scanned code, every command audited, every output deterministic and schema-validated, and no verdict quieter than the evidence for it.

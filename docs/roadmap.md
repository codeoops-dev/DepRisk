# Roadmap: what is done and what remains

This page is the working list behind the short [Roadmap](../README.md#roadmap) in the README. It says what each phase still needs, in the order it is meant to be done, and which items need data or a decision from the maintainer rather than code. Release versions follow the phases: pre-release `-alpha.N` until a phase is complete.

## v0.2: reachability (shipped as `0.2.0-alpha.1`, work continues before the next release)

Done: C# and JS/TS reachability, the uncertainty model, `explain`, signed OpenVEX, the benchmark harness, the bundled analyzer, `symbols template` (ADR 0024), `symbols check` (ADR 0025), the checks that stop an incomplete list or a contradictory answer from becoming `unreachable` (ADR 0023, ADR 0026), and one shared way to read option values in every command (S20).

Remaining, by who can do it:

| Item | Needs | Notes |
|---|---|---|
| Real symbol maps for real npm and NuGet advisories | The maintainer's data and judgment | Start from `deprisk symbols template`, keep them honest with `deprisk symbols check`. This is the bottleneck of the research claim |
| First real labeled benchmark dataset, then calibration and fitting of Exploit and Impact | The maintainer's data | Goes under `benchmarks/datasets/` with the first dataset |
| Numeric option parsing is stricter in `bench` than elsewhere | A decision | `bench` and `bench calibrate` accept only plain digits for `--samples`, `--seed`, `--bootstrap`, `--timeout`; `rank`, `ci`, `explain`, `vex` and `reach` also accept a sign and surrounding spaces (`--samples +300`). Harmonizing changes what some command lines mean, so it waits for a decision. The two `bench` commands also still keep their own copies of the shared risk options |
| Pinned Rust toolchain for reproducible analyzer builds | Code only | |
| Analyzers for `linux-musl-x64` and `win-arm64` | Code and CI runners | |
| Code signing and a run-time checksum check of the bundled analyzer | A signing decision | |
| Sigstore (keyless) signing of VEX documents | A trust decision | |
| JSON output for `symbols check` | Only if a consumer needs it | Would come with its own schema |

## v0.3: optimizer, plan format, `plan` and `apply --dry-run`

Not started. The design is in [`docs/method.md`](method.md) (MILP with CVaR). Proposed order, to be confirmed by an ADR before any code:

1. ADR: solver choice and how it is packaged (the optimizer is untrusted and must stay swappable), and the plan format (`plan.v1` schema).
2. A plan data model and a deterministic, solver-free baseline plan (greedy within the effort budget), so the verifier and the benchmark have something to compare against.
3. The MILP and CVaR objective behind the same interface.
4. `plan` and `apply --dry-run`; audit entries for both.

## v0.4 to v1.0

As in the README: the SPARK kernel and `verify` (v0.4), signed offline bundles and the GitHub Action (v0.5), stable formats and the preprint (v1.0). Not started.

## Rules that stay true in every phase

Offline analysis, no execution of scanned code, every command audited, every output deterministic and schema-validated, and no verdict quieter than the evidence for it.

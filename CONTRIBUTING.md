# Contributing to DepRisk

Thank you for your interest. DepRisk aims to be a precise, trustworthy tool, so contributions are held to a high bar for correctness and honesty about what works.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). For security issues, see [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Ways to contribute

- **Reports from real projects.** The most valuable contribution: run DepRisk on your code and tell us where it was right or wrong (false positives, false negatives, wrong reachability, bad plans). Negative results are welcome and credited.
- **Ecosystem parsers** and reachability support for new languages.
- **Vulnerable-symbol maps** (advisory → affected functions) with evidence.
- **Benchmark datasets** with ground truth.
- **Proof engineering** and review of the SPARK kernel.
- **Documentation** fixes and examples.

## Before you start

1. Search existing issues and discussions.
2. For anything larger than a small fix, **open an issue first** and describe the problem and the proposed approach. This avoids wasted work.
3. Design-level decisions are recorded as ADRs in [`docs/adr/`](docs/adr/). A change that alters architecture, data formats, the audit log, the kernel's properties, or CLI contracts needs an ADR (copy the template in `0001`).

## Development setup

Requirements: .NET SDK, Rust toolchain; GNAT with GNATprove only if you touch `kernel/`.

```bash
git clone https://github.com/codeoops-dev/deprisk.git
cd deprisk
dotnet build
dotnet test
```

As components land, these `make` targets become the standard entry points:

```bash
make build    # CLI, Rust analyzer, SPARK kernel
make test     # all unit and integration tests
make prove    # re-run GNATprove (required if kernel/ changed)
make bench    # reproducible benchmark suite
```

> The project is pre-alpha. If a command above does not exist yet, use the plain `dotnet`/`cargo` equivalents and check the [Feature status](README.md#feature-status) table.

## Pull request checklist

- [ ] Linked issue (or a clear description for small fixes)
- [ ] Tests added or updated; the suite passes
- [ ] Output is **deterministic** (same input, same seed → same result)
- [ ] Public contracts respected: CLI command names, exit codes, and `schemaVersion`ed formats. Breaking changes need an ADR and a version bump
- [ ] If `kernel/` changed: `make prove` passes with no unproven verification conditions
- [ ] Security-sensitive changes (parsing untrusted input, signature handling, file writes, audit log) explain the threat considered; see [docs/threat-model.md](docs/threat-model.md)
- [ ] Docs updated, and the README [Feature status](README.md#feature-status) table reflects reality
- [ ] No telemetry, no network calls during analysis commands (offline guarantee)

## Code guidelines

- Prefer small, reviewable pull requests.
- Do not remove code that looks unused unless a maintainer has confirmed it is discontinued; it may be planned work.
- Never log secrets, keys, or source contents.
- Handle untrusted input defensively: bounded sizes, no execution of scanned projects, no path traversal.
- Keep numbers honest: benchmark results come only from `deprisk bench` and are committed under `benchmarks/results/` with the exact seed and data versions. Do not hand-edit results.
- Follow `.editorconfig`. Commit messages: short imperative subject (for example, `Add NuGet lockfile parser`), body explaining why.

## Reporting bugs

Include: DepRisk version (`deprisk --version`), OS, the command, the smallest input that reproduces the problem (sanitize anything private), expected vs. actual behavior, and the relevant `deprisk explain` output if it is about a ranking.

## Review and decisions

Maintainers review as time allows. We may decline contributions that do not fit the project's scope or its correctness and security goals, and we will explain why. Larger design questions are settled in issues and ADRs, not in pull-request threads.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).

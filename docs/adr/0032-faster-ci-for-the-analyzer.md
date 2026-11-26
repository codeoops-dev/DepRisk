# ADR 0032: Faster CI for the analyzer: a cache outside releases, one optimized build per platform

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

On every push CI compiles the Rust analyzer in release mode (link-time optimization, one codegen unit, ADR 0022) on five platforms, and the lint job and the end-to-end job compiled it again on Linux, so one push paid for the slowest platform's cold build plus the package job after it. The user found the wait too long. Most pushes change no analyzer file, yet every dependency (tree-sitter and its C grammars) was downloaded and compiled again.

## Decision

- **A cache for CI, never for a release.** `analyzer-build.yml` has an input `cache` (default `false`). When true, `actions/cache@v4` restores and saves the cargo registry and `analyzers/reach/target`, keyed by platform and a hash of the toolchain pin, `Cargo.toml`, `Cargo.lock` and the analyzer sources, with the platform prefix as fallback (a changed source recompiles only the crate; a changed compiler or dependency makes cargo rebuild what it must). `ci.yml` passes `cache: true`; `release.yml` passes nothing, so a release builds from scratch from the tagged source, which is what ADR 0022 and threat T30 claim. `package.yml` and `release.yml` contain no cache step.
- **No second optimized build.** The lint/test job builds a debug binary for its protocol contract test (the release binary of the same platform is built, smoke-tested and used in `analyzer-build.yml` and `reach-e2e`). The two Rust jobs keep their own cache keys.
- `BuildCachePolicyTests` fail when the input is not off by default, a cache step is not guarded by it, the release path contains a cache, or CI stops asking for one.

## Consequences

- The first run after this change, and any run after the cache was evicted (unused for seven days, or over the repository's size limit), is as slow as before; later runs with unchanged analyzer sources skip the dependency compilation. How much faster is **not measured yet**: read the job durations of the second run.
- Caches are visible to the branch that wrote them and to branches built from it; a pull request from a fork cannot write the default branch's cache. A poisoned cache could only reach CI jobs, not a release, because the release never reads one.
- What the CI binary proves stays the same: it is built with the same profile and compiler as the release; only the way dependencies were obtained differs.

## Known limits

- Waiting for a runner (macOS Intel in particular) is not something a workflow can shorten.
- The five build jobs also install `clippy` and `rustfmt` from the pin (a few seconds each): one file serves every job.

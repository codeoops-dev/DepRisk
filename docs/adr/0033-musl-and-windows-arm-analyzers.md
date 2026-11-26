# ADR 0033: Analyzers for linux-musl-x64 (Alpine) and win-arm64

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

ADR 0022 bundled the reachability analyzer for five platforms and left two groups to build it from source: Alpine and other musl-based Linux (a glibc binary does not start there), and Windows on ARM. Both are common enough (Alpine container images, ARM laptops) that "build it yourself" was a poor answer for a tool installed with `dotnet tool install`.

## Decision

- **`linux-musl-x64`:** a statically linked binary built with the Rust `x86_64-unknown-linux-musl` target and `musl-gcc` (package `musl-tools`) on an `ubuntu-latest` runner. It is the one analyzer that is cross-compiled: the grammars' C code and the Rust code both target musl. The build job then (a) fails if the binary has a program interpreter (`readelf -l` shows `INTERP`), and (b) runs it **in an `alpine:3.22` container** and checks the answer, because a static binary also starts on the glibc runner, so the ordinary smoke test proves little for it.
- **`win-arm64`:** built natively on the `windows-11-arm` runner, like every other platform, and smoke-tested there.
- **Choosing the file at run time:** `AnalyzerLocator.CurrentPlatform()` returns `linux-musl-<arch>` when the .NET runtime identifier starts with `linux-musl-` (`IsMusl`), otherwise `<os>-<arch>` as before. The runtime identifier is used for this one decision only. On musl arm64 the name is `linux-musl-arm64`, which is not bundled, so the tool says so and names the machine; it does not pick a glibc binary that cannot start.
- **The package check** (`build/verify-package.py`) requires all seven, accepts the three-part name `linux-musl-x64`, and fails a musl analyzer that has a program interpreter.
- **One list, checked:** the platform list exists in the locator, `DepRisk.Cli.csproj`, `package.yml`, `verify-package.py`, the `analyzer-build.yml` matrix and `PACKAGE.md`. `BundledPlatformsAgreeTests` fail when they differ. `RustToolchainPinTests` allow `rustup target add <triple>` (a target of the pinned compiler) and still forbid any other toolchain choice.

## Consequences

- `deprisk reach` works out of the box on Alpine (x64) and on Windows on ARM (a .NET runtime for Windows on ARM64 runs the `win-arm64` analyzer; an x64 runtime under emulation uses `win-x64`).
- The package gets two more binaries; CI and the release get two more build jobs (the CI cache of ADR 0032 applies to both, a release builds from scratch).
- The musl analyzer is not byte-for-byte what a native build would give, and its C library is the one Rust bundles for the musl target; nothing about its behavior is verified beyond the protocol smoke test and the test suite that runs on the other platforms.

## Known limits

- **Verified only by CI, and not yet run:** the sandbox cannot download the musl target and has no Docker or Windows ARM. Likely failure points, in order: the `windows-11-arm` image (bash for `defaults.run.shell`, `rustup` present, the ARM64 MSVC tools for the C grammars), `alpine:3.22` (a tag, not a digest; it is only a smoke test and nothing it produces is shipped), and `musl-tools` from the Ubuntu archive.
- musl on arm64, 32-bit systems and FreeBSD still need the analyzer built from source (`--analyzer`).
- A distribution-specific runtime identifier (an old portable build that reports a distribution name) is not recognized as musl; .NET 8 and later report portable identifiers.

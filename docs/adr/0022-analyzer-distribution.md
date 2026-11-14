# ADR 0022: The reachability analyzer ships inside the NuGet package

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

The analyzer (ADR 0012, ADR 0019) is a separate Rust program, and the CLI runs it as a process. Until now it had to be built from source, which means that `deprisk reach` did nothing for anyone who installed the tool with `dotnet tool install`: the version people actually use. The decision to make is how an analyzer binary reaches the user, and how we know the binary in the package is the one we built from the tagged source.

## Decision

**The portable tool package carries the analyzer for five platforms, next to the tool:** `tools/net10.0/any/analyzers/<platform>/deprisk-reach[.exe]` for `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`, and `win-x64`, each with a `.sha256` file. After `dotnet tool install -g DepRisk.Cli`, `deprisk reach` works with no further step. The CLI looks for the analyzer in this order and stops at the first that exists: `--analyzer`, the `DEPRISK_REACH` environment variable, `deprisk-reach` next to the CLI, the bundled one for this platform. `PATH` is still not searched (ADR 0013).

**Why bundled binaries, not the alternatives.**
- *Separate download on first use:* a second trust decision (a URL, a checksum, a signature to verify) and a network access in a tool that is otherwise offline. Rejected.
- *RID-specific tool packages (the .NET 10 feature):* a pointer package plus one package per platform. The result for the user is the same, with more things to publish and keep in step. A reasonable later step if the package gets too large; today the five binaries add a few megabytes.
- *Build on first use:* needs a Rust toolchain on every user's machine. Rejected.
- *One statically linked binary for all Linux distributions (musl):* would also cover Alpine, but needs a different toolchain and cross compilation; not now.

**Built natively, on a runner of each platform, from the tagged source.** `analyzer-build.yml` builds with `cargo build --release --locked` (the dependencies in `Cargo.lock`, nothing cross-compiled) on `ubuntu-latest`, `ubuntu-24.04-arm`, `macos-15-intel`, `macos-15`, and `windows-latest`, and smoke-tests each binary on its own platform by sending it a request in both languages. It runs on every push and pull request, not only at release, so a platform that stops building is found when it happens.

**The package is checked before it can be published.** `build/verify-package.py` requires all five analyzers, checks that each file is an executable of the right kind and the right CPU architecture (ELF, Mach-O, PE headers; a binary staged for the wrong platform fails), that it is large enough to be the program, and that its SHA-256 equals the one in the `.sha256` next to it. `package.yml` then installs the package as a tool the way a user would and runs `deprisk reach` on a C# and an npm project without `--analyzer`, so what is tested is the bundled analyzer being found and executed after NuGet's extraction. The release publishes the package that passed these checks (the same artifact), after a build provenance attestation (`actions/attest-build-provenance`) for it.

**The execute permission.** NuGet does not keep the execute bit of files in a package. The first time the CLI uses the bundled analyzer it sets the execute permission for the users who can read the file (a file nobody but the owner can read is made executable for the owner only). It never changes the permissions of a file the user named with `--analyzer` or the environment variable.

**The version.** The analyzer carries the version of the tool (`0.2.0-alpha.1` for both); the release tag must match the package version, as before.

## Known limits

- Platforms not bundled: Alpine and other musl-based Linux, Windows on ARM, 32-bit systems, FreeBSD. On those the analyzer is built from source and passed with `--analyzer`; the message that says so names the platforms and this machine's.
- The Rust toolchain is `stable` as of the build, not pinned, so a rebuild of the same tag later can produce different bytes. The build log records the compiler version. Pinning (`rust-toolchain.toml`) and reproducible builds are later work.
- The binaries are not code-signed (no Authenticode, no Apple notarization) and the package is not author-signed with a certificate; integrity rests on the checks above, nuget.org's own package signing, and the provenance attestation. macOS arm64 binaries carry the ad-hoc signature the linker adds; a file delivered by NuGet does not carry the quarantine attribute that would trigger Gatekeeper.
- The CLI does not verify the analyzer's checksum at run time: anyone who can write into the tool's directory can replace both. The checksum files are for the release checks and for people who want to compare.
- The package grows by the size of five binaries, a few megabytes compressed.

## Consequences

- `deprisk reach`, `rank --symbols`, `ci --symbols`, `explain`, and `vex` work out of the box on the five platforms (given symbol maps, which is the remaining gap).
- The release workflow is now four jobs (build analyzers on five platforms, pack and verify, publish). A failure on any platform stops the release before anything is published.
- `deprisk doctor` shows which analyzer is used and where it was found.

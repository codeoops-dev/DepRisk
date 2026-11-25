# ADR 0031: One pinned Rust release for every build of the analyzer

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The reachability analyzer (`analyzers/reach`) is built from source on five runners for every release (ADR 0022) and linted and tested on every push. Until now each workflow installed `stable`, whatever that meant on the day. Two consequences: a rebuild of the same tag later could use another compiler, and a new Rust release could turn the CI red (new lints under `-D warnings`) without any change of ours. ADR 0022 and threat T30 listed this as a known limit.

## Decision

**One file names the compiler:** `analyzers/reach/rust-toolchain.toml` with `channel = "1.89.0"` (an exact release, never a channel name), `profile = "minimal"` and the components `clippy` and `rustfmt`.

- Every workflow gets its compiler with `rustup toolchain install` run in `analyzers/reach`, with no argument: rustup reads the file. No workflow names a version or a channel of its own, so there is one place to change. A developer who runs `cargo` in that directory gets the same release (rustup picks the file up; with rustup 1.28 or newer the first use needs `rustup toolchain install` once).
- `1.89.0` is the lowest release the crate declares (`rust-version = "1.89"`), and the one the analyzer's format, lint (`-D warnings`) and tests were run with in this slice (41 + 54 tests). It is not "the newest": a bump is a deliberate change of that one line, checked by CI.
- The build log prints `rustup show active-toolchain`, so the compiler used is in every run.
- `rust-version` in `Cargo.toml` stays the floor for people who build from source with their own toolchain; the pin may be equal to it or newer, never older.
- `RustToolchainPinTests` (in the normal test run) fail when the pin is not an exact release or is older than `rust-version`, when a workflow names any other toolchain (`rustup toolchain install stable`, `rustup default`, a toolchain action), or when a job runs `cargo` before installing the pinned one.

## Consequences

- The same tag is built with the same compiler later; a new Rust release cannot break the CI on its own.
- A security fix in the compiler or standard library is not picked up automatically: the pin is bumped by hand. Nothing reminds us today; the roadmap carries it as a periodic task.
- Not claimed: byte-for-byte reproducible builds. Absolute paths, the linker and the runner images are not pinned, and the five binaries are built on five different systems.

## Known limits

- `rustup` itself comes from the runner image and downloads the release from the Rust project's servers; DepRisk adds no check of its own on that download.
- Verified only in the sandbox: the analyzer passes `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and `cargo test --locked` with 1.89.0. The argument-less `rustup toolchain install` on the GitHub runners (Linux, macOS, Windows) is verified by the first CI run.

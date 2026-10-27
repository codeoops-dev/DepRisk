# ADR 0004: Component contracts and process boundaries

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

DepRisk is built from components in different languages: a .NET core and CLI, a Rust reachability analyzer, and an Ada/SPARK verification kernel. They must evolve independently, be testable in isolation, and stay on the right side of the trust boundaries in the [threat model](../threat-model.md). A mistake in how they talk to each other is expensive to fix after release.

Alternatives considered for the .NET ↔ Rust and .NET ↔ SPARK links:

1. **In-process FFI (P/Invoke).** Fast, but couples memory models and build tooling, widens the trusted boundary, and makes crashes in the analyzer take down the CLI.
2. **Local server/RPC.** Adds lifecycle management and a network-like surface, which conflicts with the offline and minimal-surface goals.
3. **Separate processes with explicit file/stdin-stdout contracts.**

## Decision

1. Components are **separate executables** invoked by the CLI as child processes. No FFI, no daemons, no sockets.
2. **CLI ↔ analyzer (Rust):** one JSON request on stdin, one JSON response on stdout, errors on stderr, non-zero exit code on failure. Both documents carry `schemaVersion`.
3. **CLI ↔ kernel (SPARK):** a deliberately minimal **line-oriented ASCII format** with integer values only (no JSON), specified in `kernel/` when the kernel is built. Rationale: parsing JSON inside SPARK is costly to prove and enlarges the trusted code. The CLI converts plans to this format; the kernel answers `ACCEPT` or `REJECT <property>` and sets its exit code accordingly.
4. All files DepRisk writes for later runs or other tools (scan results, plans, audit entries, bundle manifests) are described by **JSON Schemas in `schemas/`** and carry a `schemaVersion`.
5. **Versioning rules** are in `schemas/README.md`: additive changes keep the version; breaking changes need a new version and an ADR; readers reject unknown major versions with exit code 4.
6. **Exit codes** are the stable enumeration defined in `DepRisk.Core.ExitCode` and documented in the README. Contract tests lock their values.
7. Each component must run **without network access** and must treat all input as untrusted.

## Consequences

- A crash or hang in the analyzer or kernel is contained; the CLI can time out and report it.
- Components can be built, tested, versioned, and replaced independently; the contract tests (schemas, exit codes, golden inputs and outputs) are the integration safety net.
- Process start-up adds latency; acceptable for batch analysis, and batching requests in one invocation keeps it low.
- Two formats (JSON and the kernel's line format) must be kept in sync by a converter in the CLI, which is covered by tests and is outside the kernel's trusted base. The kernel re-checks everything it relies on.
- Changing any contract needs an ADR, a schema or format update, and updated contract tests in the same pull request.

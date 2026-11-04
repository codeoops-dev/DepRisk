# ADR 0013: The `reach` command

- **Status:** Accepted
- **Date:** 2026-11-04

## Context

ADR 0012 defined the analyzer and its protocol. This ADR decides how the CLI uses it: where the symbols come from, how the analyzer is found and trusted, how verdicts combine with what the CLI knows (direct or transitive, ecosystem), and what `deprisk reach` prints and records.

## Decision

**Command.** `deprisk reach [path] --advisories <...> --symbols <file|dir> [--source dir] [--entrypoints auto|public-api|none] [--entrypoint Ns.Type.Method]... [--analyzer file] [--timeout seconds] [--ecosystem ...] [--format table|json] [--out file] [--strict]`. It runs the same scan and matching as `match` (same inputs, same `--strict`), so the findings are exactly the ones `match` reports; then adds a reachability verdict to each. Offline. Exit codes as elsewhere: 0 success (also when findings exist; gating on reachability is a later slice), 4 for input and configuration errors, 5 when the analyzer fails or breaks the protocol.

**Symbols come from symbol maps** (`docs/symbol-maps.md`, `schemas/symbol-map.v1.schema.json`), because OSV has none for NuGet. An entry is found by advisory id or any alias, and package. `complete` and `source` are required fields without defaults: whoever writes a list decides, and the provenance travels with the verdict. A malformed map is an error that names the file and entry; nothing is skipped quietly.

**Verdicts the CLI decides itself, around the analyzer's.**
- No symbol list for the finding: `unknown` / `no-symbols`. The finding is not sent to the analyzer.
- The analyzer says `unreachable` but the package is not a direct dependency of any project where the finding occurs: `unknown` / `transitive-package-code-not-analyzed`. A path (`reachable`, `possibly-reachable`) stays, because a path from the application's own code is real evidence; absence of one is not, since the package's own code is not analyzed.
- Ecosystem without an analyzer (npm): `unknown` / `no-analyzer-for-ecosystem`; no process is started.
- If nothing has a symbol list, the analyzer is not needed and not looked up.

**Finding the analyzer, and not trusting a search path.** In order: `--analyzer`, the `DEPRISK_REACH` environment variable, the directory of the `deprisk` executable. The `PATH` is **not** searched: this process parses untrusted source code and is started by a security tool, so it must be one the user named or installed with the tool. An explicit choice that does not exist is an error, never a fallback. If none is found, the command fails with instructions (build it with `cargo build --release --locked` in `analyzers/reach`). `deprisk doctor` reports what it finds. Until the analyzer ships next to the .NET tool, the NuGet package alone cannot run `reach`.

**Running it.** One child process, no shell, no arguments, the request on stdin, the result read from stdout with a size limit, a time limit (default 300 s, `--timeout`, at most 3600) that stops the whole process tree. A start failure, a non-zero exit, a timeout, or a result that does not follow the protocol (checked field by field, with the keys matched against the request) is an error: no verdict is printed from an answer that cannot be trusted.

**Provenance.** The result records the analyzer's name, version, and the SHA-256 of the executable, the SHA-256 of the symbol maps, and the analyzer's `sourceDigest` (the identity of exactly the files it read). The audit record's inputs digest covers the findings' inputs, the symbol maps, the entrypoint choices, the analyzer hash, and the source digest. The same inputs give the same output; the JSON has no timestamps and no absolute paths.

**Source root.** The directory of the scan path (or `--source`). The whole tree is analyzed as one program (ADR 0012).

**Output.** `schemas/reachability.v1.schema.json`. The table lists findings most urgent first (reachable, possibly reachable, unknown, unreachable), each with the reason in words, the symbol reached, the path (names, last file and line, a marker for dynamic edges), and where the symbols come from. The footer states what the labels are not: exploitability.

## Known limits

- C# only. JavaScript and TypeScript need their own analyzer behind the same protocol.
- The symbol data is only as good as the maps. DepRisk ships none; the fixtures are format examples. A shared, curated source is a later question.
- `reach` is separate from `rank` and `ci`: the labels are not in the ranking or the policy gate yet (next slice).
- Findings are keyed by advisory and package: all versions of a package for one advisory share one question and one answer.

## Consequences

- The meaning of `unreachable` is narrow and visible: complete list, fully read source, no unreadable reflection or receiver, direct package.
- The CLI can be tested with a fake analyzer (a script), and the analyzer with its own suite; a CI job runs both together on fixtures.

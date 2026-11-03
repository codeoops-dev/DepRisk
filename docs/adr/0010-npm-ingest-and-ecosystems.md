# ADR 0010: npm ingest and the ecosystem model

- **Status:** Accepted
- **Date:** 2026-11-03

## Context

Until now DepRisk read NuGet only. The README promises NuGet and npm ingest for v0.1, and the first real users of a dependency risk tool are often full-stack teams. npm differs from NuGet in ways that matter for correctness: the same package can be installed several times at different versions in one project, a package can be installed under an alias, a repository can have workspaces, and versions are SemVer 2.0 (no fourth part) where NuGet's are a superset.

## Decision

**Ecosystems are a closed set.** `Ecosystem` (Core) names each one: its identifier in result files and on the command line (`nuget`, `npm`), its OSV name, and which version strings are valid for it. Adding an ecosystem is a code change with an ADR, not configuration.

**Input: `package-lock.json`, lockfileVersion 2 and 3, the `packages` map.** lockfileVersion 1 (npm 6 and older) has no such map and is rejected with a hint; any other version is rejected, never guessed at. The legacy `dependencies` tree of version 2 is ignored (the `packages` map has the same information). Only the lock file is read: nothing is executed, nothing is resolved over the network, `node_modules` is not read.

**One result model.** `ScanResult` stays as it is. An npm lock file becomes one project with one target named `npm`. `ResolvedPackage` gets an optional `path` (the lock key, for example `node_modules/a/node_modules/b`) because the same id and version can be installed at several places; it is null for NuGet. The schema version stays 1: the change is additive.

**Reading rules.**
- Aliases (`"foo": "npm:bar@1"`): the package is `bar` (the entry's `name`), because advisories are about the real package; direct/requested use the key `foo`.
- Direct: the project, or a workspace member, asks for the package (dependencies, devDependencies, optionalDependencies, non-optional peerDependencies) and it is installed at the top level of the project or of that member. `requested` is the constraint of the owner at that location. An optional peer is "works with", not "asks for".
- Workspace members, `file:` directories, and `link: true` entries are first-party code: not looked up in advisories, but what they ask for counts as direct.
- A package's `dependencies` are its dependencies, optionalDependencies, and non-optional peerDependencies, as written (for the hypergraph slice).
- Names and keys are validated against what npm can write; invalid ones, duplicate keys, a missing root entry, and a missing version are input errors (exit 4), not skipped entries. A lock file that cannot be trusted should not produce a quiet "no findings".

**Versions.** npm versions must be strict SemVer 2.0 (three numeric parts, no leading zeros, no `v`, no ranges). Valid ones are compared with the existing SemVer 2.0 implementation. A package version that is not strict SemVer is counted in `packagesSkipped` and never matched; an OSV range event that is not strict SemVer makes that record invalid (counted, and an error with `--strict`).

**Matching.** `AdvisoryIndex`, `OsvParser`, and the snapshot loader take an `Ecosystem`; only entries whose OSV ecosystem equals its name (ignoring case; vendor ecosystems such as `Echo:npm` are other ecosystems) are used. The advisory data is read for the ecosystem that was actually found. The snapshot digest identifies the data, not the ecosystem. Several installed copies of the same id and version are one finding with one location per project and target, direct if any copy is direct.

**Choosing the ecosystem.** `scan`, `match`, `rank`, `ci`, and `graph` take `--ecosystem auto|nuget|npm` (default `auto`). Auto looks at what is found: only assets files means NuGet, only lock files means npm, a path to a file is decided by its name (`project.assets.json`, `package-lock.json`). A tree with both is an error that asks the caller to choose, because silently scanning one half of a repository is the kind of quiet gap this tool exists to avoid. `node_modules` is never entered. A file with another name needs an explicit `--ecosystem`.

**Renamed field.** `advisories.skippedNotNuGet` becomes `advisories.skippedOtherEcosystem` in findings and ranking results (and `OsvParseStatus.NotNuGet` becomes `OtherEcosystem`), because the count is now relative to the scanned ecosystem. This is a deliberate break of schema v1 before 0.1.0; the published 0.0.1-alpha.2 used the old name.

**`graph` stays NuGet-only** in this slice and says so (exit 4). npm needs path-based resolution and node-semver ranges; that is the next slice (done in ADR 0011).

## Known limits (recorded, not hidden)

- Prerelease identifiers are compared ignoring case (shared implementation); SemVer compares them as plain ASCII. Only two prerelease versions of one package that differ only in the case of a label are affected.
- A package installed from a git URL, a local tarball, or a non-default registry is matched by name and version as if it came from the npm registry. A fork with the same version may be fixed or differently vulnerable. `resolved` is not evaluated yet.
- `dev`, `optional`, and `peer` flags are not part of the result: a finding in a development dependency is still a finding, and `--fail-on` cannot exclude it yet.
- `npm-shrinkwrap.json` is not read. The JSON depth limit for lock files is 128 (other inputs: 64), because lockfileVersion 2 nests its legacy tree two levels per `node_modules` level.
- A tree with both ecosystems needs two runs (one per `--ecosystem`).

## Consequences

- `rank` and `ci` (policy gate, SARIF) work for npm with no changes of their own: they only see findings. SARIF locations point at `package.json` next to the lock file when it exists, else at the lock file.
- NuGet output gains `"path": null` on every package (same pattern as `requested`).
- The next slice (hypergraph for npm) can use `path` and `dependencies` as they are.

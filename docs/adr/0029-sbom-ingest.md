# ADR 0029: CycloneDX and SPDX SBOM ingest

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

`scan`, `match`, `rank`, `ci`, `explain`, `vex` and `reach` start from a lock or assets file. Many projects hand over an SBOM instead (a supplier's, or one generated in CI), and the roadmap lists CycloneDX and SPDX ingest. An SBOM differs from a lock file in what it records: components with a Package URL (purl), and relationships between them; no version ranges, no install paths, no project file.

## Decision

**What is read.** `SbomParser` reads CycloneDX JSON (specVersion 1.2 to 1.7) and SPDX JSON (2.2 and 2.3) into the existing model: one project, one target named `sbom`, one package per component that has a purl of type `nuget` or `npm`. The field names of both formats were checked against the published JSON schemas (CycloneDX 1.2 to 1.7, SPDX 2.2 and 2.3). XML, SPDX tag-value, RDF and YAML, and SPDX 3 (JSON-LD) are not read: JSON is parsed by `System.Text.Json` with a depth limit and nothing is resolved or fetched. Components without a purl, and of other purl types (maven, pypi, ...), are not read: DepRisk matches NuGet and npm advisories.

**One ecosystem per scan, as for lock files (ADR 0010).** An SBOM with both NuGet and npm components is an error that asks for `--ecosystem`; with it, the other ecosystem is not read. An SBOM with no component of the named ecosystem, or of either, is an error.

**Found only when named.** An SBOM is read when `scan` and the commands built on it are given its path and the name is `bom.json`, `sbom.json`, `*.cdx.json` or `*.spdx.json`, or the ecosystem is named and the file, whatever its name, is a CycloneDX or SPDX document. A directory scan never picks one up: an SBOM is usually generated from the lock file next to it, so finding both would count the project twice, and documentation or test directories hold sample SBOMs that are not the project.

**The root is the project, not a dependency.** CycloneDX `metadata.component` and what an SPDX document describes (`documentDescribes`, `DESCRIBES`, `DESCRIBED_BY`) are the project even when they carry a purl (npm's own SBOMs do).

**Direct and transitive come from the relationships, and they must be there.** CycloneDX `dependencies`; SPDX `DEPENDS_ON` and the `*_DEPENDENCY_OF` types (`DEPENDENCY_OF`, `DEV_`, `OPTIONAL_`, `PROVIDED_`, `TEST_`, `RUNTIME_`, `BUILD_`; the second element depends on the first). A component is direct when the root depends on it. An SBOM that records no relationships, or whose root has no entry, or that does not say which component is the project, is **refused** with a message that says what to generate. "Direct" decides `direct` in a policy and whether a VEX document may say `not_affected` (ADR 0016); marking every component transitive would let a `direct` gate miss findings, and marking every component direct could let `not_affected` be claimed for a package that is not direct. A flat component list cannot say, so the SBOM is not guessed at (the same reasoning as npm lockfileVersion 1 without its package.json, ADR 0027).

**What the model gets.** The version of a component is the one in its purl (the `version` field only when the purl has none; no version at all is recorded as `unknown`, counted as skipped and never matched). The same id and version under several parents is one package. Dependencies are by id with an empty range; `requested` and `path` are null. Purl qualifiers and subpaths are dropped, never copied, because they can carry a repository or download URL and so a credential (ADR 0027); versions pass through `UrlCredentials.Mask`. A purl that is not a purl, or a NuGet or npm purl with a name or version the package manager could not have written, is an input error, not a silent skip.

**`graph` refuses an SBOM.** The hypergraph needs the ranges a package declares and, for npm, where it is installed; an SBOM records neither, and the npm builder would drop every package without a path and report an empty graph. `ScanOutcome.IsSbom` carries the fact, and `HypergraphService` refuses with a message that says which files to pass. Everything built on the findings (match, rank, ci, explain, vex, reach, symbols) works.

## Consequences

- No schema change except the description of `assetsFile` (it can be an SBOM file name); the scan result of an SBOM has the same shape.
- The inputs digest of an SBOM is the digest of its bytes and its name, in the same format as for a lock file.
- With `reach`, the source directory is the directory of the SBOM unless `--source-root` is given.

## Known limits

- The two real files in the tests were written by npm 10.9.9 (`npm sbom`), one per format. The NuGet fixtures are written by hand in the shape of CycloneDX files from NuGet tools (none was available); no SPDX file from a NuGet tool was seen.
- SPDX documents that relate packages only by `CONTAINS` (some generators do this for container images or directories) are refused, because they have no dependency relationship to read.
- CycloneDX 1.7 and SPDX 2.3 field names were read from the published schemas, not from files written by tools that produce them.
- A component with no `bom-ref` (CycloneDX) cannot be named by a relationship, so it is read but is never direct and has no dependencies.
- Components of other ecosystems are not mentioned in the output; the scan covers NuGet and npm only, as it does for a directory that also has a `pom.xml`.
- Scopes (`optional`, `excluded`) and the SPDX relationship type are not used: every component is read, as dev dependencies are in lock files.

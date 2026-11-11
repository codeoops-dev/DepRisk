# ADR 0020: npm projects in the CLI reachability commands

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

ADR 0019 taught the analyzer JavaScript and TypeScript. The CLI sent only NuGet findings to it; npm findings got `unknown` with the reason `no-analyzer-for-ecosystem`. `reach`, `rank`, `ci`, `explain`, and `vex` all go through one service (`ReachService`), so wiring npm in is a matter of choosing the analyzer's language, the symbol maps, and the entry point names by ecosystem, and keeping every rule of ADR 0013 (what `unreachable` means) in force.

## Decision

**The ecosystem decides the language.** NuGet is analyzed as `csharp`, npm as `javascript` (which covers TypeScript). The request carries the language; the analyzer's answer must be in that language, otherwise it is a protocol error (exit 5), never a verdict. An ecosystem with no analyzer keeps its `unknown` / `no-analyzer-for-ecosystem` path (there is none left today, the code stays for the next ecosystem).

**Symbol maps are per language.** `language` is `csharp` or `javascript`; a set is found only for its own language, so a directory can hold both and each map applies to the project it is for. A map of the other language is not an error: the result carries a diagnostic that the maps hold no entries for this ecosystem, and every finding is `unknown` / `no-symbols`.

**npm symbols are relative to the entry's package.** `symbols` such as `parse`, `Parser.parse`, `Parser.*`, `default`, `*` are composed with the entry's `package` (`lodash` becomes `lodash::template` for the analyzer). A full `package::path` is accepted when the package is the entry's package or a subpath of it (`lodash/fp::map`), so an entry cannot make claims about another package. Package names and paths are validated (`docs/symbol-maps.md`, `schemas/symbol-map.v1.schema.json`). Relative symbols keep maps short and make the common mistake (a symbol of the wrong package) impossible.

**Entry points follow the language.** `--entrypoint` is a method name for NuGet and a function id (`file.js::name`) for npm. The command line accepts both shapes; the service checks the right one once the ecosystem is known and refuses the other with a message that names the expected form.

**Nothing about the meaning of the labels changes.** `unreachable` still needs a complete symbol list, fully read sources, no unresolved reflection or receiver, and a direct dependency; a transitive-only npm package is `unknown` / `transitive-package-code-not-analyzed`, and the npm lockfile reader already knows which packages are direct (including workspace members). `explain` shows the paths with JavaScript function ids, and `vex` makes `not_affected` statements under the same conditions as for NuGet (ADR 0016).

## Known limits

- Symbol data for real npm advisories does not exist yet: OSV carries none, and the fixtures are synthetic. Writing it, or mining it from fix commits, is the next piece of work for npm.
- The CLI trusts the analyzer's `unreachable` for a symbol list marked incomplete, because the analyzer is the one that applies `complete` (ADR 0013). A second check on the CLI side would be defense in depth; it has not been added.
- Everything in ADR 0019's limits applies: no type checker, so many npm answers are `possibly-reachable` or `unknown`, and the benchmark harness (ADR 0017) is how to measure how often.

## Consequences

- `deprisk reach`, `rank`, `ci`, `explain`, and `vex` work on npm projects with the analyzer built from source and an npm symbol map.
- A scan reads one ecosystem at a time (as before), so a run uses one analyzer language; a repository with both a NuGet and an npm project is scanned once for each.

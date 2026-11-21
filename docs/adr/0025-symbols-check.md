# ADR 0025: Checking symbol maps against a project

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

`symbols template` (ADR 0024) says which advisory and package pairs have no entry. The other half of keeping a symbol map honest is the reverse question: does what has been written still apply to this project? A map is written once and the project moves on: a package is removed or upgraded past the flaw, an advisory is withdrawn or renamed, a list stays `complete: false` for ever. Nothing today says so, and a gate that only fires on a missing entry cannot stop a map from rotting.

## Decision

**`deprisk symbols check [path] --advisories <...> --symbols <file | dir>`** scans and matches the project as `reach` does, loads the maps, and reports, for the project's language only:

- **applies:** the entry matches a finding (advisory id or any alias, and package, ignoring case, as `reach` looks it up). Counted; listed only when it needs attention.
- **unused:** no finding matches the entry in this project. The package may not be installed at an affected version, or the advisory may not be in the data supplied. Listed.
- **incomplete:** an entry that applies but says `complete: false`. Listed, with what that means: verdicts can be `reachable`, `possibly-reachable` or `unknown`, never `unreachable`.
- **transitive:** an entry that applies, says `complete: true`, and whose package is only a transitive dependency everywhere it occurs. Listed, because `complete` cannot have an effect there (ADR 0013).
- **missing / not writable:** the pairs of `symbols template` (ADR 0024) that still have no entry, from the same planner.
- Entries for the other language are counted as ignored, not judged.

**An optional gate.** `--fail-on` takes a comma-separated list of `missing`, `incomplete` and `unused`; the command exits 1 when any named condition holds (exit code 1 is the policy gate, ADR 0008) and says which on standard error. Unknown terms are an input error (exit 4), as in `ci`. Without `--fail-on` the exit code is 0. `missing` counts pairs that can be drafted, not those that cannot be written at all (a gate that can never be satisfied is not a gate); those are listed and never trip it.

**Table output only, no new file.** The command writes nothing, so there is no overwrite hazard and no new JSON contract to version; a JSON form can come with its own schema if someone needs one. It is offline and audited as `symbols-check` in an initialized project (inputs digest of findings and maps, digest of the report).

**Nothing about the quality of a list.** The command cannot tell whether the symbols are right or the list is really complete; it checks that the map still fits the project and says plainly which entries claim less than they could.

## Consequences

- A CI job can fail while pairs are missing (`--fail-on missing`), or when the map has drifted from the project (`unused`), or until every list is claimed complete (`incomplete`).
- `loader`, schema, `symbol-map.v1`, and the planner are unchanged; the check reuses the planner for the missing pairs.

## Known limits

- `unused` cannot tell why no finding matches (package absent, version not affected, advisory missing from the data); it names the possibilities.
- No JSON output, no `--out`.
- Entries are judged per advisory and package, not per installed version.

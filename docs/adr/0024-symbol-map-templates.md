# ADR 0024: Symbol map templates

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Every verdict `deprisk reach` gives rests on a symbol map, and OSV carries no symbols for NuGet or npm (ADR 0013), so someone has to write them. Writing them is the bottleneck of the whole reachability claim: for a project with many findings the first problem is not what to write but which advisory and package pairs still have no entry, and what the writer needs to know about each (the installed versions, what fixed it, whether the package is a direct dependency).

A starting file is easy to build and easy to get wrong. A file that carries a guessed symbol or a default `complete` is a claim nobody made; an empty entry that the loader skips is "no symbols known" by accident. Both are exactly what the rules of ADR 0013 and ADR 0023 exist to prevent.

## Decision

**`deprisk symbols template [path] --advisories <...>`** finds the findings of the project the way `reach` does (scan, then match), groups them by advisory id and package (the same unit as one question to the analyzer, whatever the versions), and:

- prints a worklist (the default `--format table`): per pair the aliases, the installed versions, direct or transitive, the advisory's summary and the versions that fix it, and a line when the package is only transitive, because then even a complete list cannot make the finding `unreachable` (ADR 0013);
- drafts a symbol map (`--format json`, or `--out <file>` with any format) with one entry per pair that has none. `--symbols <file | dir>` names the maps that already exist; pairs they cover (by id or alias, in the project's language, exactly as `reach` looks them up) are left out and shown as `covered`, with `(incomplete)` when the entry says `complete: false`.

**The draft is built to be refused.** Each entry has `"symbols": []`, `"complete": null` and `"source": ""`. `SymbolMapLoader` rejects every one of those (a missing source, a missing decision about `complete`, an empty list), names the file and the entry, and stops the command, so a draft left in a `--symbols` directory fails `reach` instead of reading as "no symbols known", and it can only be used after a person has made all three decisions. `complete` is `null`, not `false`: the schema says it has no default, and pre-filling the safe value would make it one.

**No symbol is ever proposed.** The command knows no more than OSV does; a guess would be a claim without a source.

**An existing file is never replaced without `--force`.** This differs from the other commands, which overwrite their output, because a draft that someone has filled in is hand-written work and the command's own output is the one thing that would silently destroy it. If no pair is missing, nothing is written and the command says so.

**Pairs that cannot be an entry are reported, not drafted.** An advisory id or package name with characters or a length a symbol map does not accept is listed as `NOT WRITABLE` with the reason. The planner keeps its own copy of the name rules (the loader's are private); a test checks that the two agree on a table of names, and fails if they drift.

**Informational, audited.** Exit 0; in an initialized project an audit entry `symbols-template` records the inputs digest (findings and existing maps), the digest of the draft and the file written. The loader, the schema and `symbol-map.v1` are unchanged.

## Consequences

- The writer sees the worklist for a real project in one command and starts each entry from the right advisory id and package, with the three decisions left to them.
- The draft cannot become a claim by accident: leaving any blank makes every command that reads symbol maps fail with the entry named.
- A draft is not a valid symbol map, so `check-jsonschema` against `symbol-map.v1` fails on it too, on purpose.

## Known limits

- It lists what is missing; it does not check a finished map against the project or the advisories (a `symbols check` is possible and not added), and it has no gate mode that fails a build while entries are missing.
- It does not read upstream fix commits or package contents, so it cannot suggest candidate symbols (the third source in the README's method is not built).
- Rows are per advisory and package, not per version: an entry applies to every installed version of the package, as everywhere else.

# Symbol maps

`deprisk reach` answers "can the vulnerable code be reached from my application?" It needs to know **which symbols** of a package are the way in. OSV advisories carry no such data for NuGet, so it comes from a *symbol map*: a JSON file you supply with `--symbols <file | directory>`.

A symbol map is a claim made by whoever writes it. DepRisk validates the file and keeps the provenance, but it cannot check the claim. Read this page before relying on an `unreachable` verdict.

## Format

`schemas/symbol-map.v1.schema.json` is the contract. Example (a made-up advisory; it says nothing about a real one):

```json
{
  "schemaVersion": 1,
  "language": "csharp",
  "entries": [
    {
      "advisory": "GHSA-xxxx-xxxx-xxxx",
      "package": "Some.Package",
      "symbols": [
        "Some.Package.Parser.Parse",
        "Some.Package.Parser.#ctor",
        "Some.Package.Legacy.*"
      ],
      "complete": false,
      "source": "analyst notes, 2026-11-04: read from the fix commit and the advisory text"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `advisory` | The advisory id, or **any alias** (for example the CVE id). Matched ignoring case. |
| `package` | The NuGet package id the flaw is in. Matched ignoring case. |
| `symbols` | The public entry points through which application code reaches the flaw: `Namespace.Type.Member`, `Namespace.Type.#ctor` (the constructors), or `Namespace.Type.*` (any member of the type, including constructors). Properties count as members. Overloads are not told apart. |
| `complete` | **Required, no default.** `true` only if you claim the list contains *every* public way to reach the flaw. |
| `source` | **Required.** Where this list comes from: a reference, a commit, a person. It is shown next to the verdict. |

A file can be a directory of `.json` files (read recursively, in a fixed order). Two entries for the same advisory and package are merged conservatively: the symbols of both, and `complete` only if both say so.

## What `complete` does

- `complete: true` and no path to any listed symbol, with every source file read and nothing that could hide a path (see ADR 0012): the verdict is **`unreachable`**.
- `complete: false` and no path: the verdict is **`unknown`** (`symbol-list-incomplete`). This is the honest default for a list written from partial knowledge.
- A path is a path either way: `reachable` (static edges only) or `possibly-reachable` (dynamic edges needed).

So an incomplete list can still *prove reachability* but can never *prove unreachability*.

The rule is enforced in two places: the analyzer answers `unknown` for a list that is not complete, and the CLI turns an `unreachable` for such a list into `unknown` (`symbol-list-incomplete`) with a diagnostic if an analyzer ever says it (ADR 0023). Neither depends on the other being correct.

## Writing a good entry

- List the **public** API that leads to the flaw, not the internal method that contains it: application code can only call public members. If the flaw is inside an internal helper, list every public member that can end up there, and say `complete: true` only if you checked that.
- Prefer the type wildcard (`Ns.Type.*`) when you cannot tell which members are affected. It is less precise (more reachable verdicts) and safer.
- Include constructors (`#ctor`) when constructing the type is enough (for example a vulnerable parser that does its work in the constructor).
- Subclassing: a project type that derives from a type you list with `.*` is treated as using it.
- Write the `source` so that someone else can check the claim.

## npm packages (JavaScript and TypeScript)

For npm projects the map's `language` is `"javascript"` (a directory may hold maps of both languages: each applies to its own ecosystem, and the result says when a map for the other language was ignored). An entry is the same as for NuGet: `advisory`, `package` (the npm name, `lodash` or `@scope/pkg`), `symbols`, `complete`, `source`. The symbols name members of what the package exports:

| Symbol | Meaning |
|---|---|
| `template` | the export `template` of the package (`require('pkg').template`, `import { template } from 'pkg'`) |
| `Parser.parse` | a method of an exported type, through an instance or a subclass |
| `Parser.*` | any member of the exported type, and constructing or extending it |
| `default` | the default export, or the module value itself for a CommonJS package (`require('pkg')()`) |
| `*` | any use of the package, including a bare `import 'pkg'` |
| `lodash/fp::map` | a member of a subpath module, written in full; the part before `::` must be the entry's package or a subpath of it |

A symbol with no `::` is read relative to the entry's package; the analyzer is asked about `package::symbol` (ADR 0019). A use of a subpath of a package (`lodash/fp/map`) that is not listed matches every symbol of the package, because which member it stands for is not known. `complete` means the same as for NuGet: only `true` lets a missing path become `unreachable`. For npm that also needs the package to be a direct dependency (of the root package or of a workspace member): a package that is only a dependency of a dependency is `unknown` (`transitive-package-code-not-analyzed`), whatever the analyzer found, as for NuGet.

`--entrypoint` names a function by its id in the result (`src/app.js::handler`, `src/app.ts::Svc.run`, or `src/app.js::*` for every function of a file) instead of a C# method. By default (`auto`) the entry points are the modules nobody imports with what they export, and decorated classes; for a library use `--entrypoints public-api`.

## Starting a map: `deprisk symbols template`

```bash
deprisk symbols template . --advisories NuGet.zip --out symbols/draft.json            # what is missing, and a draft for it
deprisk symbols template . --advisories NuGet.zip --symbols symbols/ --out more.json  # leave out what the maps already cover
```

The table lists every advisory and package pair of the project that has no entry yet, with what helps to write it: the aliases, the installed versions, whether the package is direct, the advisory's summary and the versions that fix it. A pair whose package is only transitive says so, because even a complete list cannot make that finding `unreachable`. `--out` writes the draft and refuses to replace a file that exists unless you pass `--force`; with `--format json` the draft is printed (or, with `--out`, written and only a note printed).

Each drafted entry is built to be refused until you have filled it in:

```json
{ "advisory": "GHSA-xxxx-xxxx-xxxx", "package": "Some.Package", "symbols": [], "complete": null, "source": "" }
```

Fill in `symbols`, decide `complete`, and write the `source`. Until all three are done every command that reads symbol maps stops with an input error that names the file and the entry, so an unfinished draft in your `--symbols` directory can never be read as "no symbols known". Keep drafts outside that directory while you work, or give them a name that does not end in `.json`. No symbols are proposed: OSV has none for NuGet or npm, and a guess would be a claim nobody made (ADR 0024).

## Keeping a map honest: `deprisk symbols check`

```bash
deprisk symbols check . --advisories NuGet.zip --symbols symbols/
deprisk symbols check . --advisories NuGet.zip --symbols symbols/ --fail-on missing,unused   # exit 1 when a pair has no entry or an entry no longer fits
```

The report says how many entries apply to the project and lists what needs attention: **unused** entries (no finding of this project matches the advisory and package any more: the package was removed or upgraded past the flaw, or the advisory is not in the data you gave), **incomplete** entries (`complete: false`, so the verdict can never be `unreachable`), entries that say `complete: true` for a package that is only a transitive dependency (the flag cannot have an effect there), and the **missing** pairs that `symbols template` would draft. Entries for the other language are counted as ignored. `--fail-on` takes `missing`, `incomplete`, `unused` (comma-separated) and makes the command exit 1 when any holds, naming them on standard error; `missing` counts the pairs that can be drafted, not names a map cannot hold. It checks that the maps still fit the project, not that the symbols are right (ADR 0025). Table output only.

## Where the data does not apply

- **Transitive-only packages.** If the package is not referenced directly by any project, the application cannot be shown *not* to reach it through the code of the packages that use it, and that code is not analyzed. A path from the application's own code is still `reachable`; absence of one is `unknown` (`transitive-package-code-not-analyzed`), whatever `complete` says.
- **A map of the other language.** An npm project reads only `"language": "javascript"` maps and a NuGet project only `"csharp"` ones; entries for the other language are ignored with a diagnostic, and the findings are `unknown` (`no-symbols`).
- **Advisories without an entry** are `unknown` (`no-symbols`), never `unreachable`.

## Limits and validation

Files up to 16 MB, at most 1,000 files, 100,000 entries, 10,000 symbols per entry, JSON nesting up to 16. A file that does not parse, has an unsupported `schemaVersion`, an entry without `complete`, `source`, or valid symbols, or a symbol that is not valid C# syntax makes the whole command fail with the file and entry named. A symbol list that could not be read must never quietly turn into "no symbols known".

The fixtures in `tests/fixtures/reach/symbols` are examples of the format, written for DepRisk's own tests.

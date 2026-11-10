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

## Writing a good entry

- List the **public** API that leads to the flaw, not the internal method that contains it: application code can only call public members. If the flaw is inside an internal helper, list every public member that can end up there, and say `complete: true` only if you checked that.
- Prefer the type wildcard (`Ns.Type.*`) when you cannot tell which members are affected. It is less precise (more reachable verdicts) and safer.
- Include constructors (`#ctor`) when constructing the type is enough (for example a vulnerable parser that does its work in the constructor).
- Subclassing: a project type that derives from a type you list with `.*` is treated as using it.
- Write the `source` so that someone else can check the claim.

## JavaScript and TypeScript symbols

The analyzer reads JavaScript and TypeScript too (ADR 0019). Its symbols name a package and a member path instead of a C# namespace: `lodash::template`, `@scope/pkg::Parser.parse`, `pkg::default` (the default export, or the module value itself for a CommonJS package), `pkg::Type.*` (any member of the exported type, and constructing or extending it), and `pkg::*` (any use of the package, including a bare import). A use of a subpath of a package (`lodash/fp/map`) matches every symbol of the package, because which member it stands for is not known. `complete` means the same as for C#. Symbol maps for npm packages in the CLI (the `reach`, `rank`, `ci`, `explain`, and `vex` commands) are the next slice; until then the symbols are used by running the analyzer directly.

## Where the data does not apply

- **Transitive-only packages.** If the package is not referenced directly by any project, the application cannot be shown *not* to reach it through the code of the packages that use it, and that code is not analyzed. A path from the application's own code is still `reachable`; absence of one is `unknown` (`transitive-package-code-not-analyzed`), whatever `complete` says.
- **npm.** There is no analyzer for JavaScript or TypeScript yet: findings in an npm project are `unknown` (`no-analyzer-for-ecosystem`).
- **Advisories without an entry** are `unknown` (`no-symbols`), never `unreachable`.

## Limits and validation

Files up to 16 MB, at most 1,000 files, 100,000 entries, 10,000 symbols per entry, JSON nesting up to 16. A file that does not parse, has an unsupported `schemaVersion`, an entry without `complete`, `source`, or valid symbols, or a symbol that is not valid C# syntax makes the whole command fail with the file and entry named. A symbol list that could not be read must never quietly turn into "no symbols known".

The fixtures in `tests/fixtures/reach/symbols` are examples of the format, written for DepRisk's own tests.

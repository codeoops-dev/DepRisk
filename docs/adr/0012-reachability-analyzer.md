# ADR 0012: The reachability analyzer for C#

- **Status:** Accepted (analyzer and protocol; the CLI integration follows in the next slice)
- **Date:** 2026-11-04

## Context

The method (`docs/method.md`) asks, for every finding, whether the vulnerable code can actually be reached from the application. Version matching alone says "this version is affected"; most such findings are never executed. The answer must be honest in the direction that matters: **unknown is never safe** (D9). A tool that says "unreachable" and is wrong teaches people to ignore real problems.

Two facts shape the design. First, OSV has no symbol data for NuGet or npm advisories (the field exists for Go), so the symbols of a flaw must come from somewhere else: curated symbol maps, supplied by the user or by a community source. Second, a complete C# analysis needs a semantic model (Roslyn), which needs restored packages and a full build. DepRisk is offline-first and must run where nothing builds.

## Decision

**A separate process, a JSON protocol.** The analyzer is `deprisk-reach` (Rust, `analyzers/reach`): one request on stdin, one result on stdout, exit code 0 on success and 2 for an invalid request. `schemas/reach-request.v1.schema.json` and `schemas/reach-result.v1.schema.json` define the protocol; both carry `schemaVersion`, and an unknown version is rejected. Parsing untrusted source code happens in a process with its own limits and crash boundary, not inside the CLI (D4). The CLI side (symbol maps, finding-to-target mapping, process handling, labels in `rank` and `ci`) is the next slice.

**Front end: tree-sitter, no type checker.** The sources are parsed with tree-sitter-c-sharp (C# 12 syntax, collection expressions included). The analyzer builds a call graph from names, usings, aliases, `using static`, declared types, and simple inference (`new T()`, casts). It never builds the project and never reads binaries, so it works on source trees as they are. The price is that some calls cannot be resolved; the design makes sure that those cases cost precision, never soundness.

**Two kinds of edges.**
- **Static**: the front end resolved the receiver (a type named through usings, aliases, or a fully qualified name; a local, parameter, or field with a declared or inferred type; `this`, `base`) and found the member. Constructors, property accesses, and object initializer assignments count, and so does a project type that derives from a type the request names (`Ns.Type.*`).
- **Dynamic**: possible but not certain: members that override or implement the called member (class hierarchy analysis), methods passed as values, extension methods, calls on a receiver whose type is unknown (matched by member name, and only for symbols whose namespace the file imports or whose type it names), reflection by a string or `typeof` that names the type, and members that the runtime invokes (indexers, operators, finalizers, event accessors; these are entrypoints of the over-approximating search only).

**Labels.** For each target (a set of symbols):
- `reachable`: a path of static edges from an entrypoint to a symbol. The path is returned (each edge with file and line).
- `possibly-reachable`: no static path, but a path exists when dynamic edges are included.
- `unreachable`: no path even with dynamic edges, **and** nothing could hide one: every file was read completely, no reflective call with an unreadable target is reachable, no call on an unknown receiver in reachable code has the member name of a symbol whose type the file does not name, and the symbol list is declared `complete`.
- `unknown`, with the reason: `no-symbols`, `no-entrypoints`, `incomplete-analysis` (a file was skipped, too large, timed out, or has syntax the grammar could not read; or nesting was too deep), `unresolved-reflection`, `unresolved-receiver`, `symbol-list-incomplete`.

The labels are statements about the modeled call graph, not about runtime behavior.

**Entrypoints.** `auto`: `Main`, top-level statements, public instance methods of controllers (class names ending in `Controller`, or derived from `Controller`, `ControllerBase`, `ApiController`, `Hub`, `PageModel`), and the start/stop/execute methods of hosted services. `public-api`: public members of public types (for libraries). `explicit`: names given by the caller. A tree with no entrypoint is `unknown`, never `unreachable`. Using a type runs its initializers, so a static field initializer is reachable with its type.

**The symbol list is a claim.** A target's symbols are the *public entry points through which application code reaches the flaw* (`Namespace.Type.Member`, `.#ctor`, or `.*`). `complete: true` says the list has all of them. The analyzer cannot check that; it makes the claim visible and refuses to turn a missing path into `unreachable` without it. Where the symbols come from, and how a curated map states `complete`, is decided in the CLI slice.

**Whole tree, one program.** Everything below the root is analyzed as one program, so calls across project references are followed. A finding is reachable if it is reachable anywhere in the tree; the analyzer does not say from which project. Packages that are only transitive dependencies are not analyzed at all (their code is not source here): the CLI slice reports those as `unknown`, never `unreachable`.

**Bounds (hostile sources).** Symbolic links are never followed; `bin`, `obj`, `.git`, `node_modules`, `.deprisk`, `.vs` are not entered; at most 20,000 files of at most 2 MiB each (configurable, reported when exceeded), a total of 512 MiB, a parse time limit per file, bounded walking depth, a bounded request size. A file that hits a limit is reported and makes a missing path `unknown`.

**Toolchain.** Rust 1.89 or newer, `tree-sitter` 0.25 and `tree-sitter-c-sharp` 0.23 (needed for C# 12 syntax: with 0.21, 21 of 65 files of this repository did not parse completely). `Cargo.lock` is committed and CI builds with `--locked`; `tree-sitter-language` is pinned to 0.1.5 because 0.1.9 needs a newer Rust than the 1.89 this was verified with.

## Known limits (recorded, not hidden)

- No type checker: values whose type is only known through another library's return type are unknown receivers (dynamic edges or `unresolved-receiver`, never silence). Overloads are not resolved: calls match by name and argument count, and every candidate stays.
- Dependency injection containers, event buses, source generators, and framework callbacks beyond the entrypoint heuristics are not modeled. A method that only a container calls looks unreferenced; for applications that rely on this, set explicit entrypoints.
- Wildcard symbols (`Ns.Type.*`) on a receiver of unknown type need the file to import the namespace; unlike a named member, a filtered-out match leaves no uncertainty marker.
- `partial` and other contextual keywords used as identifiers can make the grammar report an error for that file (seen in one file of this repository). The result is `incomplete-analysis` when it matters, with the file named in the diagnostics.
- Reachability is not exploitability: the path says a call exists, not that the vulnerable condition (input, configuration) occurs.
- Only C# in this slice. JavaScript and TypeScript are a later slice with the same protocol shape.

## Consequences

- The CLI can work against a stable contract and can be tested with a fake analyzer.
- Precision improves later (semantic model, type flow) without changing the protocol or the meaning of the labels.
- Distribution of the analyzer binary (next to the .NET tool, or as a separate download) is decided with the CLI slice; until then it is built from source (`cargo build --release` in `analyzers/reach`).

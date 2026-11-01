# ADR 0009: The dependency hypergraph of the resolved graph

- **Status:** Accepted
- **Date:** 2026-10-30

## Context

The method (`docs/method.md`, section 1) models dependencies as a hypergraph: a hyperedge `e = (S_e, C_e)` constrains several packages at once, and a configuration is consistent iff every hyperedge holds. The remediation optimizer (v0.3) and the verification kernel (v0.4) will work on this structure. Before that, users get value from the structure itself: it shows which requirements the resolved package set violates (NuGet reports these as warning NU1608 and the build usually still succeeds), which packages are shared by several requirers, and the arity of the constraints. The README promises "hypergraph" for v0.1.

## Decision

`deprisk graph` builds the **hypergraph of the resolved graph** from the restore output, per project and target:

- **Nodes:** one per resolved package version, with its direct flag and, for direct dependencies, the constraint the project itself asked for (`requested`, as written in the assets file; the parser now keeps it).
- **Hyperedges:** one **per package version that requires something**: scope = the package and every package it requires; its constraint is "if the owner is at its resolved version, every requirement holds". Plus one **project hyperedge**: the project and its direct dependencies with the requested constraints. Pairwise dependencies are the special case of arity 2; a package with several dependencies has a higher arity, which is the point of using hyperedges.
- **Requirement check:** each requirement is compared with the resolved version: `satisfied` is true, false (outside the declared range: a violation), or **null when it cannot be decided** (the package is not in the resolved graph, or the range text is not understood). A hyperedge is false if any requirement is false, null if none is false but some are null, otherwise true. Nothing is guessed.
- **Ranges** are parsed by our own `NuGetVersionRange` (same reasoning as `NuGetVersion`, ADR 0006): NuGet interval notation (`[1.0,2.0)`, `(1.0,)`, `[1.0]`), a plain version (minimum, inclusive), and the comparator forms that appear in assets files (`>= 1.0`, `>= 1.0 < 2.0`, optionally with `&&` and parentheses). Floating versions and anything else are rejected, which makes the requirement undecided.
- **Statistics** per target: nodes, direct nodes, hyperedges, maximum arity, requirements, violated, undecided, and shared requirements (packages required by two or more hyperedges, the places where one upgrade must satisfy several requirers).
- **Outputs:** a table (summary plus every violated requirement and the first undecided ones), JSON (`schemas/graph.v1.schema.json`, deterministic), and Graphviz DOT as a bipartite graph (packages are boxes, each hyperedge a point node; violated requirements red, undecided dashed, unresolved packages as dashed ghost nodes; one cluster per project and target).
- `graph` is **informational**: exit code 0 even with violations (a policy gate on violations can be added to `ci` later). It writes an audit entry in an initialized project.
- **Safety:** package names and ranges are untrusted. The DOT writer cleans control characters and writes every identifier and label as a properly escaped quoted string (a hostile name cannot add statements); the Graphviz parser accepts the output in the tests that include quotes and backslashes in names. Table output uses the terminal-safe cleaner.

## Not done on purpose

- **Candidate versions and allowed tuples `C_e`.** The optimizer needs, for each package, the set of versions it may move to and, per hyperedge, which version combinations are allowed. That requires package-feed metadata (all versions and their dependency lists) and belongs to v0.3 with a data-source ADR. The current graph is the *constraint structure and its check for the current configuration*.
- **Family constraints and policy constraints** (pins, "no major bump", license allow-lists) of method section 1: they come from configuration, which does not exist yet.
- **npm** (S7) and other ecosystems reuse the same structure; node-semver range semantics are a separate, larger parser.
- A **graph-based policy gate** (for example "fail on any violated requirement") and a streaming/large-graph mode.

## Consequences

- The same structure will feed the optimizer, the kernel's input format (ADR 0004 line format), and visualisations, so its JSON schema is a contract from now on.
- Users can already find real problems: requirements that the resolved set violates, and heavily shared packages.
- Understanding of ranges is limited by design; undecided requirements are counted and listed so the limit is visible, not hidden.

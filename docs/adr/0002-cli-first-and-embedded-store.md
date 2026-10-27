# ADR 0002: CLI-first, no server, embedded local store

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

DepRisk must be easy to try, easy to script, usable in CI, and usable on air-gapped hosts. The project is maintained by a very small team, so every moving part (a web UI, a server, a database) multiplies the maintenance burden and the attack surface. Early adopters (including security-conscious companies) will evaluate it by running a few commands on one project.

Alternatives considered:

1. **Web service with UI and PostgreSQL.** Rich for teams, but heavy to install and operate, harder to run offline, larger attack surface.
2. **CLI with PostgreSQL.** Requires a database before first use.
3. **CLI with an embedded database.** Zero setup.

## Decision

- DepRisk is a **command-line tool first**. There is no server and no web UI in the initial releases.
- State lives in an **embedded SQLite store** under the project (`.deprisk/`). The storage layer is behind an interface so other backends can be added.
- All analysis commands work **offline** and make no network calls; fresh data enters through signed bundles.
- Output formats (`json`, `sarif`, `openvex`, `table`) are the integration surface for other tools and dashboards.

## Consequences

- Fast first run, simple CI usage, small attack surface.
- Team-level features (shared history, multi-user dashboards) are deferred. A PostgreSQL-backed team mode is on the roadmap; the storage interface exists to make it possible without redesign.
- SQLite will not scale to very large multi-project histories; this is acceptable for the target use and is flagged so it is revisited if usage demands it.
- Any future UI or server must consume the same CLI/library contracts and must not weaken the offline and audit guarantees.

# Schemas (public contracts)

Every file DepRisk writes for other tools or for later runs is described here with a JSON Schema (draft 2020-12) and carries a `schemaVersion` field.

| Schema | Used by | Status |
|---|---|---|
| [`audit-entry.v1.schema.json`](audit-entry.v1.schema.json) | audit log (`.deprisk/audit.log`, one JSON object per line) | draft |

Planned: `scan-result`, `plan`, `reach-request` / `reach-response` (analyzer protocol), `bundle-manifest`.

## Rules

1. **Additive changes** (new optional fields) keep the same `schemaVersion`.
2. **Breaking changes** (removed or renamed fields, changed meaning or type) require a new `schemaVersion`, a new schema file (`...v2...`), and an ADR.
3. Readers must reject unknown **major** schema versions with a clear error (exit code 4).
4. Contract tests validate real outputs against these schemas in CI.
5. The verification kernel does **not** read JSON; its input format is specified separately (see ADR 0004).

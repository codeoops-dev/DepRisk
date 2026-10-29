# ADR 0006: Advisory data and matching

- **Status:** Accepted
- **Date:** 2026-10-28

## Context

`deprisk scan` knows which package versions a project uses. To say which of them are vulnerable, DepRisk needs advisory data and a way to decide whether a version is affected. Requirements: offline operation (README, ADR 0002), no telemetry, deterministic results, untrusted input handled safely, and results that can be tied to the exact data they came from.

## Decision

### Data: OSV records, supplied as local files

- Advisory data is in the **OSV schema** (https://ossf.github.io/osv-schema/). It is the common format of the GitHub Advisory Database, and OSV publishes a ready-made dump per ecosystem (for NuGet: `https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip`, one JSON file per advisory).
- `deprisk match --advisories <path>` reads a **directory** of `*.json`, a **`.zip`** of them, or a single `.json`. It never downloads anything. Getting the data onto the machine is the user's step (or, from v0.5, a signed bundle, see the roadmap).
- Zip entries are **read in memory, never extracted**. Limits: 1,000,000 records, 8 MiB per record (measured on the real decompressed bytes, not on the size the archive declares), 2 GiB in total. Symbolic links are not followed.
- The result records the **source name and a SHA-256 digest** of the data (the file's digest for a zip or json, a digest of per-file digests for a directory). The audit entry binds that digest to the scan's input digest.

### What counts

- Only affected entries whose ecosystem is exactly **`NuGet`**. Vendor ecosystems such as `Echo:NuGet` (which use their own version schemes, for example `8.0.0+echo.1`) are skipped and counted, never mixed in.
- **Withdrawn** records are skipped and counted.
- A record that cannot be read is **counted as invalid and reported loudly** (a warning in the table output, `skippedInvalid` in the JSON). Skipping a record could hide a vulnerability, so `--strict` turns it into an error (exit 4). A range containing a version that is not a valid NuGet version makes the record invalid.

### Version ordering: our own `NuGetVersion`

- Comparing versions is implemented in `DepRisk.Core.Versioning.NuGetVersion` (about 200 lines), following NuGet's published rules: up to four numeric parts, missing parts are zero, a release is above its prereleases, prerelease labels are compared one by one (numeric numerically and below alphanumeric, alphanumeric case-insensitively), build metadata is ignored.
- **Why not the `NuGet.Versioning` package.** DepRisk is a supply-chain security tool, so each dependency must earn its place. The need is small and precisely specified; an own implementation keeps the tool dependency-free, lets the ordering be reviewed and tested in one place, and is fully verifiable without restoring packages. This replaces the earlier plan to use `NuGet.Versioning`.
- **Risk:** subtle divergence from NuGet's own comparer. **Mitigation:** a conformance test table (ordering of every pair in a documented chain, equality and normalization cases, rejected inputs). **Revisit** if a divergence is reported; a test-only differential check against `NuGet.Versioning` is a possible follow-up (it would not ship in the tool).

### Range evaluation (per the OSV schema)

- `ECOSYSTEM` and `SEMVER` ranges are evaluated; `GIT` ranges are ignored (they describe commits, not package versions).
- Events are processed in ascending version order (at equal versions: introduced, fixed, last_affected). `introduced` makes a version affected from that version on (`"0"` means from the very first); `fixed` ends it at that version (exclusive); `last_affected` ends it after that version (inclusive). Unknown event kinds (for example `limit`) are ignored.
- A version is also affected if it appears in the explicit `versions` list (ranges and lists are combined).
- Package ids match **case-insensitively**, as NuGet ids do.
- `fixedVersions` of a finding are the `fixed` events of the ranges that matched, restricted to versions **above the installed one**, ascending. The first is the smallest known upgrade. Empty means no known fix.

### Output

- `deprisk match` produces `findings.v1` (`schemas/findings.v1.schema.json`): per advisory and package version, the locations (project, target, direct or transitive), the database's own severity rating, published scores (carried, not interpreted), and the fixed versions. Deterministic: no timestamps, no absolute paths, fixed ordering.
- `match` is **informational**: exit code 0 even when there are findings. Policy gates (exit code 1) come with `deprisk ci`.
- Matching is **by version only**. The output says so; reachability comes in v0.2.

### Untrusted text

Summaries, ids, and package names come from the advisory data. Table output replaces control characters (including the escape character that starts terminal control sequences) and bounds lengths. JSON output escapes them. Summaries are truncated to 500 characters when read.

## Consequences

- Fully offline and reproducible: same scan plus same data gives byte-identical output.
- The tool is only as complete as the data supplied; the output states this and reports what was skipped.
- A new threat-model entry covers hostile or poisoned advisory data and terminal injection (T15, T16).
- Signed, versioned data bundles (v0.5) will wrap this same record format; the loader stays the same.
- Severity scoring (CVSS base scores, EPSS, KEV) is the next slice (`rank`); `match` deliberately carries the published vectors without interpreting them.

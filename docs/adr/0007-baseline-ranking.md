# ADR 0007: Baseline ranking (KEV, EPSS, CVSS)

- **Status:** Accepted
- **Date:** 2026-10-29

## Context

The project's claim is that risk-aware, uncertainty-driven prioritization beats what teams do today. A claim like that needs a **reference method** to be measured against (the evaluation plan names it B2: "CVSS plus EPSS and KEV"). `deprisk rank` provides it, using three widely available public signals:

- **CISA KEV**: the catalog of vulnerabilities known to be exploited in the wild.
- **EPSS** (FIRST): the estimated probability that a CVE is exploited in the next 30 days.
- **CVSS**: the severity score, published with advisories as a vector string.

## Decision

### Ordering: lexicographic tiers, no invented weights

Findings are ordered by these keys, each only separating findings that are equal on the keys before it:

1. listed in KEV (listed first)
2. EPSS probability (higher first)
3. CVSS base score (higher first)
4. the advisory database's own severity rating (higher first)
5. advisory id, package id, version (for a stable, deterministic result)

A finding without data for a key sorts after findings that have it. `null` means "not available", never "zero". There is no weighted sum, so no weights or thresholds had to be made up; the order can be explained in one sentence, which is what a baseline should offer. The method name `baseline-kev-epss-cvss` and the key list are part of the output.

### Signals

- **CVE mapping.** A finding's CVEs are its id and aliases that have the CVE form. EPSS: the highest probability among them. KEV: listed if any is in the catalog.
- **CVSS: our own v3.0/v3.1 base-score implementation** (`DepRisk.Core.Cvss.CvssV3`), from the FIRST specification, tested against a table of published scores. When an advisory carries several v3 vectors, the highest base score is used (conservative). **CVSS v4.0 and v2 vectors are not scored** (the v4 equations rely on large lookup tables; implementing them correctly deserves its own slice); they are carried as published by `match`, and findings with only such vectors fall back to the database severity rating. As with `NuGetVersion` (ADR 0006), a small, precisely specified algorithm is implemented in-house to avoid a dependency, and covered by tests.
- **EPSS** is read from FIRST's `epss_scores-*.csv` or `.csv.gz` (a first line starting with `#` carrying the model version and score date, the header `cve,epss,percentile`, one row per CVE). **KEV** is read from CISA's `known_exploited_vulnerabilities.json` (catalogVersion, dateReleased, a `vulnerabilities` array with `cveID`, `dateAdded`, `knownRansomwareCampaignUse`). Both are **local files supplied by the user**; nothing is downloaded.
- Malformed rows or entries are counted and reported (a warning in the table, `skipped` in the JSON); `--strict` turns them into an error.
- Gzip input is decompressed with a limit on the **real** decompressed size, so a gzip bomb cannot exhaust memory.

### Output

`ranking.v1` (`schemas/ranking.v1.schema.json`): the findings of `match` plus `rank` and a `signals` object (cvss, epss, kev) per finding, and provenance for each data set: file name, SHA-256 of its bytes, and the **version and date published inside the data** (never the current time, so output stays deterministic). The audit entry's inputs digest covers the scan, the advisories, EPSS, and KEV.

### Not done on purpose

- No score blending, no thresholds ("EPSS above X is urgent"). Those are modeling choices to be evaluated, not hard-coded.
- No freshness policy yet. The dates are shown; deciding that data is too old needs a clock and a policy (planned with signed bundles, v0.5).
- No reachability and no uncertainty: this is the baseline.

## Consequences

- The evaluation can state exactly what the new model adds over B2, using the same inputs.
- Stale EPSS or KEV data silently degrades the ranking, so the data's own dates and digests are always printed.
- A hostile or wrong EPSS/KEV file could reorder findings; see the threat model (T17). Signed bundles later address provenance.
- CVSS v4 support, a freshness policy, and a score-blending variant (to be evaluated, not assumed) are follow-ups.

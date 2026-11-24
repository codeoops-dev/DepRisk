# ADR 0028: CVSS v4.0 base scoring

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

ADR 0007 scored CVSS v3.0 and v3.1 with an implementation of the FIRST specification and left v4.0 vectors unscored, because the v4.0 equations rest on a lookup table of 270 macro vectors and a distance procedure that deserved its own slice. Advisories now carry v4.0 vectors (OSV type `CVSS_V4`), and a finding with only such a vector fell back to the database severity rating, which is coarser and ranks below any scored finding.

## Decision

**`CvssV4` scores a v4.0 vector, `CvssScorer` picks the version.** `CvssV4.TryScore` is a port of the reference calculator FIRST publishes (`FIRSTdotorg/cvss-v4-calculator`: `cvss_score.js`, `cvss_lookup.js`, `max_composed.js`, `max_severity.js`; BSD-2-Clause, notice in `THIRD-PARTY-NOTICES.md`). The vector is reduced to six equivalence classes (a macro vector), the macro vector's score comes from the 270-entry table (`CvssV4Lookup`, generated from `cvss_lookup.js`, not edited by hand), and the score is lowered by the mean of the distances to the highest-severity vector of each class that has a lower macro vector. The floating-point operations are in the reference's order and its rounding (half up) is kept, so the scores are the reference's scores.

- **Base score only (CVSS-B).** Like `CvssV3`, only the base metrics (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA) are scored. Threat (E), Environmental (CR, IR, AR, the Modified metrics) and Supplemental metrics are checked (known name, valid value) and then ignored; the returned vector is the canonical base vector. A vector with an unknown metric or value, a duplicate, a missing base metric, or another prefix (`CVSS:4.1`) is not scored, rather than scored on a guess.
- **`CvssScorer.TryScore`** tries v3.x then v4.0. `BaselineRanker` uses it, so the CVSS signal of a finding is the **highest base score among its v3.x and v4.0 vectors** (the rule of ADR 0007, now over both versions); on a tie the later version wins. Everything that reads the signal (the baseline order, the risk model's impact factor, `cvss>=N` in policy, SARIF, `explain`, the benchmark's B1 and B2) therefore sees v4.0 scores. v2 vectors are still not scored.
- **Shared parts.** The qualitative rating bands are the specification's for both versions (`CvssV3.Rating`), and `CvssScore`/`CvssV3.Format` are shared.

## Verification

The reference code was run (Node) on all 104,976 base vectors and compared with the C# scorer: no difference. `CvssV4Tests` keeps 218 of those vectors (every 500th, all that score 10.0, every 30th of the zeros) with the reference's scores, plus the parsing rules. The files the port is based on, fetched from the `main` branch on 2026-11-24, have the SHA-256 `d533fe62…165e` (`cvss_lookup.js`), `453ce676…a1bc` (`cvss_score.js`), `be707cc8…9f63` (`max_composed.js`) and `f838ecb4…0b24` (`max_severity.js`).

## Consequences

- Output that changes: a finding whose advisory has a v4.0 vector now has a `cvss` signal (`version` `4.0`) where it had none, or a higher one where the v4.0 score is the highest; ranks, risk estimates and `cvss>=N` gates can move accordingly. An advisory with no v4.0 vector is unchanged.
- The `ranking` and `explain` schemas allow `"4.0"` in `cvss.version` and `CVSS:4.0/` in `cvss.vector` (`schemaVersion` stays 1: a value that was not possible before is now possible; no field changed name, type or meaning). A consumer that validates with a copy of the earlier schema would reject a finding with a v4.0 score.
- Two output texts say what they cover: the B1 description of `bench` ("CVSS base score only, v3.x or v4.0") and the `explain` evidence line when there is no score ("No CVSS v3.x or v4.0 score is available ...").
- `THIRD-PARTY-NOTICES.md` is new and is packed with the tool.

## Known limits

- v3 and v4 scores are on the same 0 to 10 scale and bands but are not calibrated against each other; "highest wins" is conservative, not a claim that they measure the same thing. No effort is made to prefer one version.
- Threat and Environmental metrics are ignored, so a vector that says `E:U` scores as if exploitation were attacked (`E:A`), as a base score does. Using them is a design question for the risk model, not for the scorer.
- The table and the procedure are those of CVSS 4.0. A later minor version of the standard (4.1) is refused until it is added deliberately; if FIRST corrects the reference, the port must follow (the differential run above is the way to check it).

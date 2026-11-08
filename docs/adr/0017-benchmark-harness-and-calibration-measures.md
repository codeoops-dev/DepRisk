# ADR 0017: The benchmark harness and the calibration measures

- **Status:** Accepted
- **Date:** 2026-11-08

## Context

Everything the uncertainty model does today rests on placeholder parameters (ADR 0015), and the README promises that benchmark numbers are produced by `deprisk bench` and by nothing else. Before any parameter is fitted or any claim is made, the tool needs a way to ask, on data with known outcomes: *does ordering by the risk model find the findings that mattered earlier than the baselines do, is the analyzer's "unreachable" safe to act on, and are the model's probabilities honest?* The harness must also be hard to fool: an evaluation where the signals already contain the outcome, or where the same data is used to tune and to report, proves nothing.

## Decision

**The harness runs the product, not a copy of it.** `deprisk bench` calls the same `RankPipeline` as `rank`, `ci`, `explain`, and `vex` (scan, match, optional reachability, baseline ranking, risk model) on every case, so a benchmark can never describe a different tool from the one people run. Offline, deterministic, no network.

**A dataset is a manifest** (`schemas/bench-manifest.v1.schema.json`, format in `docs/benchmarks.md`): cases, each a project with the advisory data, optional EPSS and KEV files, optional symbol maps and source, and the ground truth as labels keyed by advisory (id or alias) and package: `exploited` (exploited in the wild within the outcome window) and `reachable` (the vulnerable code is truly reachable; `null` when not established). Every case belongs to the split `dev` or `test`. A manifest says whether it is `synthetic`; a synthetic result says so in the table and in a warning, and the repository never reports its numbers.

**A temporal split guards against leakage.** The manifest fixes `signalsAsOf`, and the outcome window must start on or after it. Every EPSS and KEV file is checked against that date when the case runs: data dated after it is refused, and data whose publication date cannot be read is refused too (it cannot be shown to predate the outcomes). This is exit code 4, not a warning, because a leaked benchmark produces flattering numbers.

**Held-out use is explicit.** `--split` defaults to `dev`. Reporting on `test` carries a warning that tuning on it invalidates the result; `all` carries a warning that it is not a held-out result. Parameters are fitted on `dev` only (the fitting itself is a later slice).

**Methods compared.** B1: CVSS only (ties by database severity, then id; the exploitation signals never break a tie). B2: the baseline of `rank` (KEV, EPSS, CVSS). B3 in two forms, both ordered as B2: *naive* (keep only findings the analyzer calls reachable) and *conservative* (drop only those called unreachable, keep unknown and possibly-reachable); a case without symbol maps keeps all its findings under both. The risk model, ordered by the chosen statistic. B4 (upgrade everything), the residual-risk-versus-effort curve, the post-plan build pass rate and the plan verification time need the planner and the kernel and are listed as not evaluated in every result, not silently absent.

**Metrics.** Over the labeled findings of each case: average precision, recall@k and precision@k (k = 1, 3, 5, 10, capped at the number presented), and the *alert fraction to full recall* (the share of a case's findings a reader goes through from the top to have seen every exploited one). Averages are macro averages over cases that have at least one exploited finding, so a large project does not drown small ones. A filtering method that removes an exploited finding is shown as such (`suppressed`, `exploitedMissed`); its alert fraction is averaged only over cases where it still presents all of them and is reported as `n/N`, so it cannot look good by hiding a miss. Uncertainty: a seeded bootstrap that resamples **cases** (findings of one project are not independent), 95% percentile intervals with integer nearest ranks, and paired differences (risk model minus each other method on the same resamples). Intervals are computed only when at least two cases have an exploited finding.

**Reachability against truth.** A table of label by truth, coverage (the share not `unknown`), strict and lenient precision and recall, and the number that matters most for suppression: *unsound unreachable*, findings the analyzer called `unreachable` that truly are reachable.

**Calibration.** Reliability tables, Brier score, log loss (probabilities clipped to [1e-6, 1-1e-6]), and expected calibration error (ten equal-width bins) for: the model's Exploit factor against `exploited`, the raw EPSS probability against `exploited`, and the model's Reach factor against `reachable`; and for each reachability label the observed reachable rate next to the mean Reach factor, which is exactly the input of calibrating the Reach priors. The loss distribution itself cannot be calibrated: public ground truth records events, not losses (listed as not evaluated).

**The manifest is untrusted input.** Strict (unknown properties are errors), bounded (16 MB, 5000 cases, 100,000 labels per case, 500,000 in total, depth 16), with control characters refused in every text, unique case ids and unique labels, and every path relative, existing, inside the directory of the manifest, and reached without passing through a symbolic link. Nothing the manifest names is executed except through the analyzer path the user passes on the command line.

**Deterministic output.** Rounded to six decimals, no timestamps or absolute paths, the model seed and the bootstrap seed recorded; the audit record covers the manifest digest, the split, and the per-case input digests (which include the model parameters).

## Known limits

- The ground truth is only as good as its source. "Exploited" is usually "observed to be exploited" (for example, added to KEV after the signals date), which is a biased sample of what happened; "reachable" needs manual or dynamic confirmation and is expensive, so it is often `null`. The dataset documentation says how each label was obtained (`labelSource`), and the result repeats it.
- A leakage guard can check the dates of EPSS and KEV; it cannot check that advisories or symbol maps were not written with knowledge of the outcome. That remains the dataset author's responsibility.
- With a handful of cases the intervals are wide or degenerate; the result states the number of cases, and an interval from fewer than a few dozen cases with an exploited finding should be read as indicative.
- Macro averaging over cases ignores how large a case is; a pooled (micro) view is a possible addition.
- B3 is a straw man in its naive form on purpose (it is the common practice); the conservative form is the fair comparison.
- The model's probabilities are compared with events, not with losses; Impact is not validated by this harness.

## Consequences

- A change to the model or to its parameters can be judged on the same labeled cases before it ships, with the same seed.
- Fitting the Reach priors from the observed rates per label, and the first real dataset, are the next steps; neither is claimed here.
- Results that mix development and test cases are visibly marked, so a held-out number cannot be produced by accident.

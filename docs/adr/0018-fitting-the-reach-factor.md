# ADR 0018: Fitting the Reach factor on the development split

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

ADR 0015 left every parameter of the uncertainty model as a placeholder, and ADR 0017 added the measures that say how well they work. The first parameter that labeled data can speak to directly is `Reach`: for each reachability label (`reachable`, `possibly-reachable`, `unknown`, `unreachable`, and findings never analyzed) the model uses a Beta distribution for the probability that the vulnerable code is really exercised. A benchmark with a reachability truth per finding observes exactly that probability, as a rate.

## Decision

**`deprisk bench calibrate --cases <manifest> --out <risk-params.json>` fits the Reach factor and nothing else.** For a label with `n` findings of known truth, `k` of them truly reachable, and a Beta(a, b) prior, the factor becomes Beta(a + k, b + n - k): the posterior of the rate at which code carrying that label is really reachable. The distribution is epistemic, so it narrows as evidence accumulates, which is what the sampling in the model should reflect.

**Development split only.** The fit reads the cases of the `dev` split and no others; there is no option to include `test`. The evaluation is a separate step on held-out data: `deprisk bench --split test --risk-params <file>`. If `bench` is run with parameters that say they were fitted on the same dataset and the split is not `test`, the result carries a warning.

**The fit uses nothing but the label and its truth.** The analysis runs without EPSS, KEV, and the risk model, so the leakage guard of ADR 0017 has nothing to check here and the fitted numbers cannot depend on the exploitation signals.

**The prior is explicit.** The default is the uniform Beta(1, 1): no opinion, so the numbers come from the data. `--prior current` takes the parameters the fit starts from (the defaults, or the file passed with `--risk-params`) as the prior, so the counts update them; this is the choice for a user who trusts the placeholders as an informed starting point.

**A label needs enough data.** A label with fewer than `--min-count` findings of known truth (default 20) keeps its current parameter, and the table says "kept". The number is a judgement, not a result: it stops a handful of cases from replacing a placeholder with noise (two samples would turn Beta(1, 49) for `unreachable` into Beta(1, 3), thirty times more pessimistic). If no label reaches it, nothing is written and the command exits with 4, because a file that changes nothing would still look calibrated.

**The file is complete.** The output contains every parameter (Reach as fitted or kept, Exploit and Impact as they were) plus an optional `provenance` note (dataset name and manifest digest, split, counts per label, prior, minimum, and a marker if the dataset is synthetic). The numbers are written out so that the file means the same when a later version of the tool ships other defaults. The note is informational: the model ignores it and the parameters digest does not cover it, so the same numbers have the same digest. Results made with the file say `calibration: custom`, as for any parameters file; the `ranking.v1` contract is unchanged.

## Known limits

- A fit is tied to the analyzer that produced the labels. When the analyzer or its symbol maps change, the observed rates change; fit again.
- The rate is pooled over findings and projects. It ignores that findings of one project are correlated, so the posterior is narrower than the evidence deserves when few projects carry many findings. A hierarchical model over projects is a later option.
- Labels with `reachable: null` are left out, so the fit assumes that the truth is missing at random. If truth was established mainly for findings that look reachable, the rates are biased; `labelSource` should say how truth was chosen.
- Exploit (EPSS concentration, the no-EPSS prior, the KEV means) and Impact are not fitted. They can be calibrated by the same method against `exploited` and are listed as open work.
- A fit is a point in a space of choices (prior, minimum); the same dataset under another prior gives other numbers. The provenance note records them.

## Consequences

- Placeholder numbers can be replaced by numbers with a stated origin, judged on held-out data with the same harness.
- The first real dataset decides whether any of this is meaningful; until then the command is tested on a synthetic dataset and its output says so.

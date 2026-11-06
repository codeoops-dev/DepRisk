# ADR 0015: The uncertainty model (risk distributions by Monte Carlo)

- **Status:** Accepted (model and machinery; the parameters are placeholders until calibrated)
- **Date:** 2026-11-05

## Context

`docs/method.md` (section 4) defines the risk of a finding as `R = Reach x Exploit x Impact`, each a random variable, reported as quantiles over seeded scenarios, so that "probably fine but catastrophic if wrong" can outrank "probably fine and mild". The baseline `rank` (KEV, then EPSS, then CVSS) is the reference this model is compared with. Until now only the baseline existed. Reachability (ADR 0012 to 0014) is the first signal that is really uncertain, so the model can now use it.

The method states that the parameters are **to be calibrated** on labeled benchmark cases. There are no such cases yet. This ADR therefore separates two things: the model and its machinery, which are fixed and tested here, and the numbers, which are explicit placeholders that are visible in every output.

## Decision

**Command.** `deprisk rank --model risk` (and `ci`, which shares the options). `--model baseline` is the default and unchanged. Options: `--samples N` (100 to 200,000; default 5000), `--seed N` (a 64-bit number), `--rank-by mean|p50|p90|p95|cvar95` (default `mean`; `cvar` is accepted for `cvar95`), `--risk-params <file>`. These options without `--model risk` are an input error. The risk model uses reachability when `--symbols` is given; without it every finding is "not analyzed".

**The model.** For each finding, draw `S` scenarios of `(Reach, Exploit, Impact)` and report the distribution of the product.
- `Reach ~ Beta` by the reachability label (placeholders): reachable Beta(9,1) mean 0.90; possibly-reachable Beta(4,2) 0.67; unknown Beta(2,2) 0.50; not analyzed Beta(2,2) 0.50; unreachable Beta(1,49) 0.02. Unknown and not analyzed are never treated as unreachable, and unreachable is small but not zero because the analyzer is a model, not an oracle.
- `Exploit`: with an EPSS value `p` (clamped to [0.001, 0.999]) it is Beta(p k, (1-p) k) with concentration k = 20, so that the forecast has uncertainty around its published value; without EPSS, the wide prior Beta(0.5, 9.5) (mean 0.05). A finding in the CISA KEV catalog has its mean raised to at least 0.70 (known ransomware use: 0.85) with concentration 10: KEV is strong evidence and is never lowered by a small EPSS.
- `Impact = Uniform(3, 6) x SeverityFactor`: the asset-criticality range (a placeholder for the policy file of the method; the README's `default_impact`) times a severity factor: the CVSS base score / 10 if known, else a point factor for the database rating (low 0.2, moderate 0.5, high 0.75, critical 0.95), else Uniform(0.1, 1.0), so that missing severity widens the distribution instead of being guessed.
- The three factors are independent within a finding, and findings are independent of each other. Correlation (same package, same call path) is a known simplification and a research question.

**Reproducibility.** The generator is fully specified (xoshiro256** seeded through SplitMix64, Marsaglia-Tsang gamma sampling, Beta as a ratio of gammas) and implemented in the code base, not taken from `System.Random`, whose algorithm is not part of its contract. A pinned test fixes its first outputs. Every finding has its own random stream derived from the seed and the finding's key (`advisory|package|version`, case-insensitive): a finding's numbers do not depend on which other findings are present or on their order. The default seed is derived from the parameters and the number of samples only (not from the data), so that new advisories do not change the numbers of existing findings. A given `--seed` is recorded as such. Results are rounded to six decimals. Within one platform the output is byte-identical; across platforms the underlying floating-point library functions may differ in the last bits, which the rounding hides in practice but does not guarantee.

**Output.** `ranking.v1` (additive): `method` is `risk-monte-carlo`, `ordering` is `risk.<statistic>` then `baseline-rank`; per finding `risk` (mean, p50, p90, p95, cvar95, and the means of the three factors) and `baselineRank` (the position the baseline would give); top-level `model` (samples, seed as a decimal string, seed source, statistic, calibration, a digest of the parameters, and the parameters themselves). Quantiles are empirical by the nearest-rank rule; cvar95 is the mean of the worst 5% of scenarios. Ties keep the baseline order. SARIF gets `riskMean` and `riskP95` properties. The table states the method, the calibration, and that the numbers are not probabilities of real-world loss.

**Calibration is explicit.** `calibration` is `uncalibrated-defaults` for the built-in numbers and `custom` for a parameters file (`schemas/risk-params.v1.schema.json`: the defaults with any numbers replaced). A parameters file is strict: an unknown property is an error, because a misspelled parameter that is silently ignored would run the placeholders while the user believes calibrated values are in use. Parameters are validated (positive, finite, in range).

**Limits (hostile or careless input).** Samples are bounded, and findings times samples may not exceed 100 million scenarios; the parameters file is limited to 1 MB and nesting depth 8; all parameters are range-checked so that no sampler can loop or overflow.

## Research questions this opens

1. Does ranking by a tail statistic (p95, cvar95) beat ranking by the mean, and by the baseline, on labeled cases? (The default `mean` is the standard decision-theoretic choice, not a conclusion.)
2. Calibration: what Beta parameters per reachability label, and what EPSS concentration, give calibrated forecasts on the benchmark? Is the analyzer's measured precision per label a usable source for the Reach parameters?
3. What does correlation between findings (same package, same call path) change in the ranking and in portfolio statistics?

## Known limits

- The placeholders are not evidence. The ordering they produce is a hypothesis that must be compared with the baseline (the output carries both ranks so that it can be).
- Impact uses a global range; per-asset criticality from a policy file is not implemented.
- The model sees one EPSS and one KEV signal per finding, the first that applies to its identifiers.
- Scenarios are independent across findings, so no portfolio-level statistic (for example the risk of the whole set, or CVaR of the sum) is produced yet; that belongs to the optimizer.

## Consequences

- The reference ordering stays what it was; the new one is opt-in and labeled.
- Calibration later changes numbers, not structure: the parameters, their digest, and the calibration label are already in every result.
- The optimizer can reuse the same scenarios and streams.

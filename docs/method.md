# Method Specification

Status: **design draft.** This document specifies the model DepRisk is built to implement. Numeric parameters (priors, calibration constants) are intentionally **not fixed here**: they are set by calibration on the benchmark suite and recorded with each release. Where a quantity is "to be calibrated", no default value is claimed.

Notation: `P` packages, `V_p` candidate versions of package `p`, `A` advisories, `S` Monte Carlo scenarios.

## 1. Dependency hypergraph

A **configuration** is a function `c` assigning each package `p ∈ P` exactly one version `c(p) ∈ V_p`.

A **hyperedge** is a pair `e = (S_e, C_e)` where `S_e ⊆ P` is its scope and `C_e` is the set of allowed joint assignments to `S_e` (each element is a tuple of versions, one per package in the scope).

A configuration is **consistent** iff for every hyperedge `e`, the restriction `c|S_e ∈ C_e`.

Sources of hyperedges:

- declared dependency ranges (a package version requires compatible versions of others),
- family constraints (packages that must share a version line),
- user policy (pins, no-major rules, license allow-lists).

Pairwise edges are the special case `|S_e| = 2`.

## 2. Advisories and fixes

Each advisory `a ∈ A` has:

- an affected package `p_a`,
- an affected version set `Aff_a ⊆ V_{p_a}` (from range data),
- a symbol set `Σ_a` (functions or modules carrying the flaw), possibly empty/unknown.

Advisory `a` is **fixed** under configuration `c` iff `c(p_a) ∉ Aff_a`. As an indicator on decision variables (section 6): `fixed_a(x) = Σ_{v ∈ V_{p_a} \ Aff_a} x_{p_a, v}`.

## 3. Reachability

Symbol set resolution, in priority order:

1. symbols listed in the advisory data,
2. curated symbol maps shipped in the data bundle,
3. symbols mined from the upstream fix commit (functions modified by the patch).

The analyzer builds a call graph `G = (N, E)` over the project and its dependencies' public API surface, from declared entrypoints. Edges are classified:

- **static edges**: resolved with certainty by the language front-end,
- **dynamic edges**: introduced conservatively for dynamic dispatch, reflection, dynamic loading, and eval-like constructs.

Label `ℓ_a` for advisory `a`:

| Label | Condition |
|---|---|
| `reachable` | a path from an entrypoint to some `σ ∈ Σ_a` using only static edges |
| `possibly-reachable` | a path exists only when dynamic edges are included |
| `unreachable` | no path in the over-approximated graph (all dynamic edges included) |
| `unknown` | `Σ_a` unavailable, or an unsupported construct prevents analysis |

`unknown` is never treated as safe. `unreachable` is a statement about the **modeled** graph, not a proof about all executions.

## 4. Risk model

For each advisory `a`:

```
R_a = Reach_a · Exploit_a · Impact_a
```

- `Reach_a ∈ [0,1]` is the probability that the vulnerable code is exercised in practice. Modeled as `Beta(α_ℓ, β_ℓ)` with parameters depending on the label `ℓ_a` and the analyzer's measured precision for that label. **Parameters to be calibrated** on labeled benchmark cases.
- `Exploit_a ∈ [0,1]` is the probability of exploitation. Derived from EPSS and KEV membership. KEV membership is treated as strong evidence (modeled by shifting the distribution); EPSS is a forecast and is modeled with forecast uncertainty (a Beta around the published value with concentration to be calibrated).
- `Impact_a ≥ 0` is drawn from the asset-criticality policy, as a point value or a range (uniform or triangular) in `deprisk.toml`.

Independence between `Reach_a`, `Exploit_a`, and `Impact_a` is assumed within an advisory. Correlation between advisories (for example, the same package or the same call path) is a known simplification; a correlated sampling model is future work and is listed as a research question.

**Scenarios.** Draw `S` independent samples (seeded; same seed gives the same result) of `(Reach_a^s, Exploit_a^s, Impact_a^s)` for all `a`, giving `R_a^s`. Reported quantiles (p50, p95) per advisory are empirical quantiles over scenarios.

## 5. Effort and cost model

For package `p` moving from current version `v0` to `v`:

```
cost(p, v0→v) = 0                                   if v = v0
              = base(Δsemver) + γ · use(p, v0→v)    otherwise
```

- `base(Δsemver)` is a table by change class (patch, minor, major, pre-release), in effort units to be calibrated.
- `use(p, v0→v) ≥ 0` measures how much of the project's actual use of `p` touches APIs changed between `v0` and `v`, from API-diff data when available; otherwise a conservative default by change class.
- `γ ≥ 0` weights the term.

Cost is in engineer-hours-equivalent units so that the budget `B` is expressed as in `--budget 6h`. Calibration against observed upgrade outcomes is part of the benchmark.

## 6. Optimization problem

Decision variables `x_{p,v} ∈ {0,1}`: package `p` ends at version `v`.

Scenario loss for plan `x`:

```
L_s(x) = Σ_a R_a^s · (1 − fixed_a(x))
```

This is **linear in x** for fixed scenario samples.

Objective, with risk-aversion `ρ ∈ [0,1]` and tail level `α ∈ (0,1)`:

```
minimize   (1 − ρ) · E[L(x)]  +  ρ · CVaR_α(L(x))
```

where `E[L(x)] = (1/|S|) Σ_s L_s(x)`.

(The README writes the equivalent additive form `E + λ·CVaR`; the convex-combination form with `ρ ∈ [0,1]` is the implemented parameterization, and `λ = ρ / (1 − ρ)` up to a scale factor. `ρ = 0` recovers expected-risk minimization.)

**CVaR linearization** (Rockafellar–Uryasev). Introduce `η ∈ ℝ` and `u_s ≥ 0`:

```
CVaR_α(L(x)) = η + 1/((1 − α)·|S|) · Σ_s u_s
subject to     u_s ≥ L_s(x) − η      for every scenario s
               u_s ≥ 0
```

Minimizing over `η` and `u` yields the exact CVaR of the empirical distribution.

**Constraints:**

```
Σ_{v ∈ V_p} x_{p,v} = 1                         for every package p          (one version each)
Σ_{p,v} cost(p, v0→v) · x_{p,v} ≤ B                                           (effort budget)
policy: x_{p,v} = 1 for pinned (p,v); x_{p,v} = 0 for forbidden pairs         (pins, no-major, license)
```

**Hyperedge consistency.** For each hyperedge `e`, introduce binaries `z_{e,t}` for each allowed tuple `t ∈ C_e`:

```
Σ_{t ∈ C_e} z_{e,t} = 1
x_{p,v} = Σ_{t ∈ C_e : t_p = v} z_{e,t}         for every p ∈ S_e, v ∈ V_p
```

The result is a mixed-integer linear program. Solvers are pluggable (default: HiGHS or CBC); the solver and its version are recorded in the plan for reproducibility.

**Size control.** Candidate versions are pruned to those that matter (the current version, versions that fix at least one advisory, and the minimal and latest compatible versions) to keep `|V_p|` small. Pruning rules are deterministic and documented in the plan.

## 7. Plan format and verification

A plan records: input digests (hypergraph, bundle, policy), seed, scenario count, solver identity, the chosen configuration (changed packages only, `from → to`), claimed fixed advisories, and total cost. It carries a `schemaVersion`.

The **verification kernel** (Ada/SPARK) takes the hypergraph, the current configuration, the plan, the budget, and the policy in a minimal integer-based format, and checks:

| Property | Check |
|---|---|
| P1 | each package has exactly one resulting version |
| P2 | every hyperedge `e` satisfied: `c'|S_e ∈ C_e` |
| P3 | `Σ cost ≤ B` (scaled integers) |
| P4 | pins, forbidden pairs, and allow-lists respected |
| P5 | every advisory claimed fixed satisfies `c'(p_a) ∉ Aff_a` |
| P6 | absence of runtime errors (proven by GNATprove) |

All arithmetic in the kernel is on scaled integers. The kernel does not recompute risk and does not verify optimality or reachability labels.

## 8. Evaluation protocol (summary)

Baselines B1–B4 and DepRisk are compared on pinned datasets with fixed seeds, using the metrics in the README (residual expected risk versus effort, alert reduction without missing known-exploited findings, reachability precision/recall, post-plan build/test pass rate, verification time, and calibration of quantiles). Parameters in sections 4 and 5 are fit on a development split and reported on a held-out split. Results are generated by `deprisk bench` and are not edited by hand.

## 9. Open research questions

1. Value of tail-risk (CVaR) objectives over expected-risk ranking at equal effort.
2. Benefit of hyperedge constraints over pairwise models in avoiding inconsistent or failing upgrades.
3. Quality of symbols mined from fix commits compared to curated vulnerable-function data.
4. Correlated risk across advisories sharing packages or call paths.
5. Calibration of `Reach` priors per label and per language.
6. Practical cost and coverage of proving plan properties with a small trusted kernel.

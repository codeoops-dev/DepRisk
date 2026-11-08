# Benchmarks: dataset format and how to read a result

`deprisk bench --cases <manifest.json>` compares the baselines (B1, B2, B3) with the risk model on labeled cases and measures reachability and calibration against ground truth. The design and its limits are in [ADR 0017](adr/0017-benchmark-harness-and-calibration-measures.md); the model is in [method.md](method.md).

> **No result is a result unless its dataset is real.** The dataset in `tests/fixtures/reach/bench-manifest.json` is synthetic (`"synthetic": true`): it exists to test the harness, and every output made from it says so. Nothing from it belongs in the README or in a paper.

## A dataset

A dataset is a directory with a manifest (`schemas/bench-manifest.v1.schema.json`) and the files its cases refer to. All paths in the manifest are relative to the manifest's directory and may not leave it or pass through a symbolic link.

| Field | Meaning |
|---|---|
| `name`, `description` | What the dataset is. |
| `synthetic` | `true` for test fixtures. Required, so nobody forgets to say. |
| `signalsAsOf` | The date the EPSS and KEV data were fixed at (`yyyy-MM-dd`). |
| `outcomeWindow.from`, `.to` | The period in which outcomes (exploitation) were observed. `from` must not be before `signalsAsOf`. |
| `labelSource` | How the ground truth was obtained (a sentence; it is repeated in every result). |
| `cases[]` | One entry per project analysis. |

A case has an `id` (letters, digits, `.`, `_`, `-`; unique), a `split` (`dev` or `test`), `path` (what `scan` reads), `advisories` (OSV data), optional `epss` and `kev`, optional `symbols` with `source`, `entrypoints` (`auto`, `public-api`, `none`) and `entrypointNames` (the options of `reach`), an optional `ecosystem`, and `labels`.

A label is `{ "advisory", "package", "exploited", "reachable" }`. `advisory` is an advisory id or any of its aliases (a CVE id, say), `package` the package id, `exploited` whether the vulnerability was exploited in the wild during the outcome window, and `reachable` whether the vulnerable code is truly reachable from the project (`null` if nobody established it). A label applies to every finding with that advisory and package. Findings without a label are left out of every metric and counted; labels that match no finding are counted too (`--strict` makes both an error).

### Building one honestly

1. Fix `signalsAsOf` first and take EPSS and KEV as published on or before that day. The tool refuses newer files, and files without a readable date.
2. Observe the outcomes only after it: for example, which of the CVEs were added to KEV during the window.
3. Split by project (or by time) into `dev` and `test` before looking at any result. Fit and tune on `dev`; look at `test` once, at the end.
4. Write down in `labelSource` how each label was obtained. Reachability truth usually needs manual or dynamic confirmation; leave it `null` rather than guess.

## Running

```
deprisk bench --cases benchmarks/datasets/<name>/manifest.json [--split dev|test|all]
              [--samples <n>] [--seed <n>] [--rank-by mean|p50|p90|p95|cvar95] [--risk-params <file>]
              [--bootstrap <n>] [--analyzer <file>] [--timeout <s>] [--strict] [--format table|json] [--out <file>]
```

`--split` defaults to `dev`. The model options are those of `rank --model risk`; `--bootstrap` is the number of resamples (default 1000, 0 switches intervals off). Same inputs and same seeds give the same bytes.

## Reading a result

- **Ordering quality.** *AP* (average precision) is higher when exploited findings come earlier; a filtered-out exploited finding counts as zero. *Alerts to full recall* is the share of a case's findings you read from the top to have seen every exploited one (lower is better), averaged over the cases where the method presents all of them (shown as `n/N`). *recall@k* is the share of a case's exploited findings within the first k. All are macro averages over cases with at least one exploited finding.
- **Suppressed / missed.** What a filter removed, and how many exploited findings were among them. A filter that looks efficient and misses exploited findings is not efficient.
- **Paired differences.** Risk model minus another method on the same resampled cases, with a 95% interval. An interval that contains 0 does not support a claim of difference.
- **Reachability.** Rows are the analyzer's label, columns the truth. *Unsound unreachable* is the number of `unreachable` calls that are truly reachable: if it is not 0, suppressing on `unreachable` is not safe on this data.
- **Calibration.** Brier score and log loss (lower is better) and ECE (the weighted gap between predicted and observed rates). The per-label table shows how often code labeled *x* was really reachable next to the Reach factor the model uses for *x*.
- **Not evaluated yet.** What needs the planner or the kernel; it is listed so it is not mistaken for passed.

Intervals from few cases are wide or degenerate. The result states the number of cases and cases with an exploited finding; do not claim more than they support.

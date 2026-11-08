using DepRisk.Core.Ranking;

namespace DepRisk.Core.Bench;

/// <summary>
/// Compares the orderings on labeled cases (docs/benchmarks.md): B1 (CVSS only), B2 (the baseline: KEV, EPSS, CVSS), B3 (B2 with a
/// reachability filter, in a naive and a conservative form), and the risk model. Pure: the caller supplies the labeled findings.
/// </summary>
public static class BenchEvaluator
{
    public const string B1 = "b1-cvss";
    public const string B2 = "b2-baseline";
    public const string B3 = "b3-reachable-only";
    public const string B3Conservative = "b3c-not-unreachable";
    public const string Risk = "deprisk-risk";

    public static readonly IReadOnlyList<string> MethodIds = [B1, B2, B3, B3Conservative, Risk];

    private static readonly int[] KValues = [1, 3, 5, 10];

    private static readonly string[] ReachLabels = ["reachable", "possibly-reachable", "unreachable", "unknown"];

    private const int MinCasesForBootstrap = 2;

    public static string Describe(string method) => method switch
    {
        B1 => "CVSS v3 base score only (ties: database severity, then id)",
        B2 => "baseline: CISA KEV, then EPSS, then CVSS (the order of 'rank')",
        B3 => "B2 order, keeping only findings the analyzer calls reachable (naive filter; findings of cases without reachability analysis are kept)",
        B3Conservative => "B2 order, dropping only findings the analyzer calls unreachable (conservative filter; unknown and possibly-reachable are kept)",
        Risk => "the uncertainty model: findings ordered by a statistic of the risk distribution",
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, "unknown method"),
    };

    /// <summary>The findings of a case in the order <paramref name="method"/> presents them (a filtering method presents fewer).</summary>
    public static IReadOnlyList<BenchFinding> Present(string method, IReadOnlyList<BenchFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        return method switch
        {
            B1 => findings
                .OrderByDescending(f => f.Cvss ?? -1)
                .ThenByDescending(f => BaselineRanker.SeverityRank(f.Severity))
                .ThenBy(f => f.Id, StringComparer.Ordinal)
                .ThenBy(f => f.PackageId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.PackageVersion, StringComparer.Ordinal)
                .ToList(),
            B2 => findings.OrderBy(f => f.BaselineRank).ToList(),
            B3 => findings.OrderBy(f => f.BaselineRank).Where(f => f.ReachLabel is null or "reachable").ToList(),
            B3Conservative => findings.OrderBy(f => f.BaselineRank).Where(f => f.ReachLabel is not "unreachable").ToList(),
            Risk => findings.OrderBy(f => f.RiskRank).ToList(),
            _ => throw new ArgumentOutOfRangeException(nameof(method), method, "unknown method"),
        };
    }

    public static BenchEvaluation Evaluate(
        IReadOnlyList<BenchCaseData> cases,
        int unlabeled,
        int labelsUnmatched,
        int bootstrapIterations,
        ulong bootstrapSeed)
    {
        ArgumentNullException.ThrowIfNull(cases);

        List<BenchFinding> all = cases.SelectMany(c => c.Findings).ToList();
        int casesWithPositives = cases.Count(c => c.Findings.Any(f => f.Exploited));

        BenchCounts counts = new(
            cases.Count,
            casesWithPositives,
            all.Count + unlabeled,
            all.Count,
            unlabeled,
            labelsUnmatched,
            all.Count(f => f.Exploited),
            all.Count(f => f.ReachableTruth is not null),
            all.Count(f => f.ReachableTruth == true));

        // Per method and per case: the metrics that are averaged.
        Dictionary<string, CaseMetrics[]> perCase = MethodIds.ToDictionary(
            m => m,
            m => cases.Select(c => Measure(m, c)).ToArray(),
            StringComparer.Ordinal);

        bool bootstrapped = bootstrapIterations > 0 && casesWithPositives >= MinCasesForBootstrap;
        IReadOnlyList<int[]> resamples = bootstrapped ? Bootstrap.Resamples(cases.Count, bootstrapIterations, bootstrapSeed) : [];

        Dictionary<string, double?[]> apSeries = [];
        Dictionary<string, double?[]> afSeries = [];

        foreach (string method in MethodIds)
        {
            apSeries[method] = bootstrapped ? resamples.Select(draw => Mean(draw, perCase[method], m => m.AveragePrecision)).ToArray() : [];
            afSeries[method] = bootstrapped ? resamples.Select(draw => Mean(draw, perCase[method], m => m.AlertFraction)).ToArray() : [];
        }

        List<BenchMethodResult> methods = [];

        foreach (string method in MethodIds)
        {
            CaseMetrics[] metrics = perCase[method];

            methods.Add(new BenchMethodResult(
                method,
                Describe(method),
                metrics.Count(m => m.Positives > 0),
                metrics.Count(m => m.AlertFraction is not null),
                metrics.Sum(m => m.Presented),
                metrics.Sum(m => m.Suppressed),
                metrics.Sum(m => m.Missed),
                BenchMetrics.Round(Average(metrics.Select(m => m.AveragePrecision))),
                BenchMetrics.Round(Average(metrics.Select(m => m.AlertFraction))),
                KValues.Select(k => new AtK(
                    k,
                    BenchMetrics.Round(Average(metrics.Select(m => m.Recall[k]))),
                    BenchMetrics.Round(Average(metrics.Select(m => m.Precision[k]))))).ToList(),
                bootstrapped ? Bootstrap.Percentile95(apSeries[method].Where(v => v is not null).Select(v => v!.Value).ToList()) : null,
                bootstrapped ? Bootstrap.Percentile95(afSeries[method].Where(v => v is not null).Select(v => v!.Value).ToList()) : null));
        }

        List<BenchDifference> differences = [];

        foreach (string versus in new[] { B1, B2, B3, B3Conservative })
        {
            differences.Add(Difference(Risk, versus, "averagePrecision", methods, apSeries, bootstrapped, m => m.AveragePrecision));
            differences.Add(Difference(Risk, versus, "alertFractionToFullRecall", methods, afSeries, bootstrapped, m => m.AlertFractionToFullRecall));
        }

        BootstrapInfo bootstrap = new(
            bootstrapped ? bootstrapIterations : 0,
            bootstrapSeed.ToString(System.Globalization.CultureInfo.InvariantCulture),
            0.95,
            bootstrapped
                ? null
                : bootstrapIterations == 0
                    ? "bootstrap switched off (--bootstrap 0)"
                    : $"needs at least {MinCasesForBootstrap} cases with an exploited finding; this selection has {casesWithPositives}");

        return new BenchEvaluation(
            counts,
            methods,
            differences,
            bootstrap,
            EvaluateReach(all),
            ReachByLabel(all),
            CalibrationReports(all));
    }

    private sealed record CaseMetrics(
        int Positives,
        int Presented,
        int Suppressed,
        int Missed,
        double? AveragePrecision,
        double? AlertFraction,
        Dictionary<int, double?> Recall,
        Dictionary<int, double?> Precision);

    private static CaseMetrics Measure(string method, BenchCaseData data)
    {
        IReadOnlyList<BenchFinding> presented = Present(method, data.Findings);
        List<bool> outcomes = presented.Select(f => f.Exploited).ToList();
        int positives = data.Findings.Count(f => f.Exploited);
        int found = outcomes.Count(o => o);
        int? alerts = BenchMetrics.AlertsToFullRecall(outcomes, positives);

        return new CaseMetrics(
            positives,
            presented.Count,
            data.Findings.Count - presented.Count,
            positives - found,
            BenchMetrics.AveragePrecision(outcomes, positives),
            alerts is null ? null : (double)alerts.Value / data.Findings.Count,
            KValues.ToDictionary(k => k, k => BenchMetrics.RecallAtK(outcomes, positives, k)),
            KValues.ToDictionary(k => k, k => positives > 0 ? BenchMetrics.PrecisionAtK(outcomes, k) : null));
    }

    private static double? Average(IEnumerable<double?> values)
    {
        double sum = 0;
        int count = 0;

        foreach (double? v in values)
        {
            if (v is { } value)
            {
                sum += value;
                count++;
            }
        }

        return count == 0 ? null : sum / count;
    }

    private static double? Mean(int[] draw, CaseMetrics[] metrics, Func<CaseMetrics, double?> select) =>
        Average(draw.Select(i => select(metrics[i])));

    private static BenchDifference Difference(
        string method,
        string versus,
        string metric,
        IReadOnlyList<BenchMethodResult> methods,
        Dictionary<string, double?[]> series,
        bool bootstrapped,
        Func<BenchMethodResult, double?> select)
    {
        double? a = select(methods.Single(m => m.Id == method));
        double? b = select(methods.Single(m => m.Id == versus));
        double? difference = a is null || b is null ? null : BenchMetrics.Round(a.Value - b.Value);

        Interval? ci = null;

        if (bootstrapped)
        {
            double?[] left = series[method];
            double?[] right = series[versus];
            List<double> diffs = [];

            for (int i = 0; i < left.Length; i++)
            {
                if (left[i] is { } l && right[i] is { } r)
                {
                    diffs.Add(l - r);
                }
            }

            ci = Bootstrap.Percentile95(diffs);
        }

        return new BenchDifference(method, versus, metric, difference, ci);
    }

    private static BenchReachEvaluation? EvaluateReach(IReadOnlyList<BenchFinding> all)
    {
        List<BenchFinding> evaluated = all.Where(f => f.ReachLabel is not null && f.ReachableTruth is not null).ToList();

        if (evaluated.Count == 0)
        {
            return null;
        }

        List<ReachConfusionRow> rows = ReachLabels
            .Select(label => new ReachConfusionRow(
                label,
                evaluated.Count(f => f.ReachLabel == label && f.ReachableTruth == true),
                evaluated.Count(f => f.ReachLabel == label && f.ReachableTruth == false)))
            .ToList();

        int truthPositives = evaluated.Count(f => f.ReachableTruth == true);
        int analyzed = evaluated.Count(f => f.ReachLabel != "unknown");

        return new BenchReachEvaluation(
            evaluated.Count,
            BenchMetrics.Round((double)analyzed / evaluated.Count),
            evaluated.Count(f => f.ReachLabel == "unreachable"),
            evaluated.Count(f => f.ReachLabel == "unreachable" && f.ReachableTruth == true),
            rows,
            Score(evaluated, truthPositives, "reachable"),
            Score(evaluated, truthPositives, "reachable", "possibly-reachable"));
    }

    private static PrecisionRecall Score(IReadOnlyList<BenchFinding> evaluated, int truthPositives, params string[] positiveLabels)
    {
        int predicted = evaluated.Count(f => positiveLabels.Contains(f.ReachLabel, StringComparer.Ordinal));
        int truePositives = evaluated.Count(f => positiveLabels.Contains(f.ReachLabel, StringComparer.Ordinal) && f.ReachableTruth == true);

        return new PrecisionRecall(
            predicted,
            truePositives,
            truthPositives,
            predicted == 0 ? null : BenchMetrics.Round((double)truePositives / predicted),
            truthPositives == 0 ? null : BenchMetrics.Round((double)truePositives / truthPositives));
    }

    private static IReadOnlyList<ReachLabelCalibration> ReachByLabel(IReadOnlyList<BenchFinding> all)
    {
        List<ReachLabelCalibration> rows = [];

        foreach (string label in ReachLabels.Append("not-analyzed"))
        {
            List<BenchFinding> group = all
                .Where(f => f.ReachableTruth is not null && (f.ReachLabel ?? "not-analyzed") == label)
                .ToList();

            rows.Add(new ReachLabelCalibration(
                label,
                group.Count,
                group.Count == 0 ? null : BenchMetrics.Round((double)group.Count(f => f.ReachableTruth == true) / group.Count),
                group.Count == 0 ? null : BenchMetrics.Round(group.Average(f => f.ReachMean))));
        }

        return rows;
    }

    private static IReadOnlyList<CalibrationReport> CalibrationReports(IReadOnlyList<BenchFinding> all)
    {
        return
        [
            new CalibrationReport(
                "exploit-model",
                "the model's mean Exploit factor",
                "exploited within the outcome window",
                Calibration.Summarize(all.Select(f => (f.ExploitMean, f.Exploited)).ToList())),
            new CalibrationReport(
                "epss-raw",
                "the published EPSS probability (findings that have one)",
                "exploited within the outcome window",
                Calibration.Summarize(all.Where(f => f.Epss is not null).Select(f => (f.Epss!.Value, f.Exploited)).ToList())),
            new CalibrationReport(
                "reach-model",
                "the model's mean Reach factor (findings with known truth)",
                "the vulnerable code is truly reachable",
                Calibration.Summarize(all.Where(f => f.ReachableTruth is not null).Select(f => (f.ReachMean, f.ReachableTruth!.Value)).ToList())),
        ];
    }
}

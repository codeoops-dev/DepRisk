using System.Text.Json;
using DepRisk.Core.Bench;
using Xunit;

namespace DepRisk.Core.Tests.Bench;

public sealed class BenchEvaluatorTests
{
    private static BenchFinding F(
        string id,
        int baseline,
        int risk,
        bool exploited,
        double? cvss,
        string? label,
        bool? truth,
        double exploitMean = 0.5,
        double reachMean = 0.5,
        double? epss = null,
        string? severity = null) =>
        new(id, "pkg-" + id, "1.0.0", baseline, risk, cvss, severity, label, exploited, truth, exploitMean, reachMean, epss);

    // Case A: baseline order A1, A2, A3; risk order A2, A3, A1; CVSS order A2, A3, A1. A2 and A3 are exploited.
    private static BenchCaseData CaseA() => new("a", new[]
    {
        F("A1", 1, 3, false, 5.0, "reachable", true, exploitMean: 0.2, reachMean: 0.9),
        F("A2", 2, 1, true, 9.0, "unknown", false, exploitMean: 0.8, reachMean: 0.5, epss: 0.7),
        F("A3", 3, 2, true, 7.0, "unreachable", true, exploitMean: 0.6, reachMean: 0.1),
    });

    // Case B has no exploited finding and no reachability analysis.
    private static BenchCaseData CaseB() => new("b", new[] { F("B1", 1, 1, false, 4.0, null, null, exploitMean: 0.1) });

    private static BenchMethodResult Method(BenchEvaluation e, string id) => e.Methods.Single(m => m.Id == id);

    [Fact]
    public void The_methods_present_the_findings_in_their_own_order_and_filters_present_fewer()
    {
        IReadOnlyList<BenchFinding> findings = CaseA().Findings;

        Assert.Equal(new[] { "A2", "A3", "A1" }, BenchEvaluator.Present(BenchEvaluator.B1, findings).Select(f => f.Id).ToArray());
        Assert.Equal(new[] { "A1", "A2", "A3" }, BenchEvaluator.Present(BenchEvaluator.B2, findings).Select(f => f.Id).ToArray());
        Assert.Equal(new[] { "A2", "A3", "A1" }, BenchEvaluator.Present(BenchEvaluator.Risk, findings).Select(f => f.Id).ToArray());

        // Naive filter keeps only 'reachable' (and findings without an analysis); the conservative one drops only 'unreachable'.
        Assert.Equal(new[] { "A1" }, BenchEvaluator.Present(BenchEvaluator.B3, findings).Select(f => f.Id).ToArray());
        Assert.Equal(new[] { "A1", "A2" }, BenchEvaluator.Present(BenchEvaluator.B3Conservative, findings).Select(f => f.Id).ToArray());
    }

    [Fact]
    public void A_case_without_reachability_analysis_keeps_all_its_findings_under_both_filters()
    {
        IReadOnlyList<BenchFinding> findings = CaseB().Findings;

        Assert.Single(BenchEvaluator.Present(BenchEvaluator.B3, findings));
        Assert.Single(BenchEvaluator.Present(BenchEvaluator.B3Conservative, findings));
    }

    [Fact]
    public void B1_breaks_cvss_ties_by_severity_then_id_and_never_by_the_exploitation_signals()
    {
        BenchFinding[] findings =
        [
            F("Z", 1, 1, false, 9.8, null, null, severity: "HIGH"),
            F("B", 2, 2, true, 9.8, null, null, severity: "CRITICAL"),
            F("A", 3, 3, false, 9.8, null, null, severity: "CRITICAL"),
            F("N", 4, 4, false, null, null, null),
        ];

        Assert.Equal(new[] { "A", "B", "Z", "N" }, BenchEvaluator.Present(BenchEvaluator.B1, findings).Select(f => f.Id).ToArray());
    }

    [Fact]
    public void Ordering_metrics_are_macro_averages_over_cases_with_an_exploited_finding()
    {
        BenchEvaluation e = BenchEvaluator.Evaluate([CaseA(), CaseB()], unlabeled: 2, labelsUnmatched: 1, bootstrapIterations: 100, bootstrapSeed: 1);

        BenchMethodResult b1 = Method(e, BenchEvaluator.B1);
        Assert.Equal(1.0, b1.AveragePrecision);
        Assert.Equal(0.666667, b1.AlertFractionToFullRecall);
        Assert.Equal(1, b1.CasesWithPositives);
        Assert.Equal(0.5, b1.AtK.Single(k => k.K == 1).Recall);
        Assert.Equal(1.0, b1.AtK.Single(k => k.K == 1).Precision);
        Assert.Equal(0.666667, b1.AtK.Single(k => k.K == 3).Precision);

        BenchMethodResult b2 = Method(e, BenchEvaluator.B2);
        Assert.Equal(0.583333, b2.AveragePrecision);
        Assert.Equal(1.0, b2.AlertFractionToFullRecall);
        Assert.Equal(0.0, b2.AtK.Single(k => k.K == 1).Recall);

        BenchMethodResult risk = Method(e, BenchEvaluator.Risk);
        Assert.Equal(1.0, risk.AveragePrecision);
        Assert.Equal(0.666667, risk.AlertFractionToFullRecall);
    }

    [Fact]
    public void A_filter_that_removes_exploited_findings_shows_it_in_suppressed_and_missed()
    {
        BenchEvaluation e = BenchEvaluator.Evaluate([CaseA(), CaseB()], 0, 0, 0, 1);

        BenchMethodResult naive = Method(e, BenchEvaluator.B3);
        Assert.Equal(0.0, naive.AveragePrecision);
        Assert.Equal(2, naive.Suppressed);
        Assert.Equal(2, naive.ExploitedMissed);
        Assert.Null(naive.AlertFractionToFullRecall);
        Assert.Equal(0, naive.CasesFullRecall);

        BenchMethodResult conservative = Method(e, BenchEvaluator.B3Conservative);
        Assert.Equal(0.25, conservative.AveragePrecision);
        Assert.Equal(1, conservative.Suppressed);
        Assert.Equal(1, conservative.ExploitedMissed);

        BenchMethodResult b2 = Method(e, BenchEvaluator.B2);
        Assert.Equal(0, b2.Suppressed);
        Assert.Equal(0, b2.ExploitedMissed);
    }

    [Fact]
    public void Differences_are_risk_minus_the_other_method_and_null_when_the_other_has_no_value()
    {
        BenchEvaluation e = BenchEvaluator.Evaluate([CaseA(), CaseB()], 0, 0, 0, 1);

        BenchDifference ap = e.Differences.Single(d => d.Versus == BenchEvaluator.B2 && d.Metric == "averagePrecision");
        Assert.Equal(BenchEvaluator.Risk, ap.Method);
        Assert.Equal(0.416667, ap.Difference);

        BenchDifference alerts = e.Differences.Single(d => d.Versus == BenchEvaluator.B2 && d.Metric == "alertFractionToFullRecall");
        Assert.Equal(-0.333333, alerts.Difference);

        Assert.Null(e.Differences.Single(d => d.Versus == BenchEvaluator.B3 && d.Metric == "alertFractionToFullRecall").Difference);
    }

    [Fact]
    public void Counts_report_what_was_labeled_what_was_not_and_what_matched_nothing()
    {
        BenchEvaluation e = BenchEvaluator.Evaluate([CaseA(), CaseB()], unlabeled: 2, labelsUnmatched: 1, bootstrapIterations: 0, bootstrapSeed: 1);

        Assert.Equal(2, e.Counts.Cases);
        Assert.Equal(1, e.Counts.CasesWithPositives);
        Assert.Equal(6, e.Counts.Findings);
        Assert.Equal(4, e.Counts.Labeled);
        Assert.Equal(2, e.Counts.Unlabeled);
        Assert.Equal(1, e.Counts.LabelsUnmatched);
        Assert.Equal(2, e.Counts.Exploited);
        Assert.Equal(3, e.Counts.ReachTruthKnown);
        Assert.Equal(2, e.Counts.ReachableTruth);
    }

    [Fact]
    public void Reachability_is_judged_against_the_truth_and_unsound_unreachable_calls_are_counted()
    {
        BenchReachEvaluation reach = BenchEvaluator.Evaluate([CaseA(), CaseB()], 0, 0, 0, 1).Reach!;

        Assert.Equal(3, reach.Evaluated);
        Assert.Equal(0.666667, reach.Coverage);
        Assert.Equal(1, reach.UnreachableTotal);
        Assert.Equal(1, reach.UnsoundUnreachable);

        Assert.Equal(new ReachConfusionRow("reachable", 1, 0), reach.Rows.Single(r => r.Label == "reachable"));
        Assert.Equal(new ReachConfusionRow("unreachable", 1, 0), reach.Rows.Single(r => r.Label == "unreachable"));
        Assert.Equal(new ReachConfusionRow("unknown", 0, 1), reach.Rows.Single(r => r.Label == "unknown"));

        // One call 'reachable' (truly so); two findings are truly reachable, so recall is one half.
        Assert.Equal(1.0, reach.Strict.Precision);
        Assert.Equal(0.5, reach.Strict.Recall);
        Assert.Equal(2, reach.Strict.TruthPositives);
    }

    [Fact]
    public void Possibly_reachable_counts_only_in_the_lenient_reading()
    {
        BenchCaseData data = new("x", new[]
        {
            F("X1", 1, 1, false, 5.0, "reachable", true),
            F("X2", 2, 2, false, 5.0, "possibly-reachable", false),
            F("X3", 3, 3, false, 5.0, "possibly-reachable", true),
        });

        BenchReachEvaluation reach = BenchEvaluator.Evaluate([data], 0, 0, 0, 1).Reach!;

        Assert.Equal(1, reach.Strict.Predicted);
        Assert.Equal(3, reach.Lenient.Predicted);
        Assert.Equal(1.0, reach.Strict.Precision);
        Assert.Equal(0.5, reach.Strict.Recall);
        Assert.Equal(0.666667, reach.Lenient.Precision);
        Assert.Equal(1.0, reach.Lenient.Recall);
    }

    [Fact]
    public void Without_analyzed_and_labeled_findings_there_is_no_reachability_evaluation()
    {
        Assert.Null(BenchEvaluator.Evaluate([CaseB()], 0, 0, 0, 1).Reach);
    }

    [Fact]
    public void Calibration_compares_each_predicted_quantity_with_what_happened()
    {
        BenchEvaluation e = BenchEvaluator.Evaluate([CaseA(), CaseB()], 0, 0, 0, 1);

        CalibrationReport exploit = e.Calibration.Single(c => c.Quantity == "exploit-model");
        Assert.Equal(4, exploit.Summary.Count);

        // (0.2^2 + 0.2^2 + 0.4^2 + 0.1^2) / 4
        Assert.Equal(0.0625, exploit.Summary.Brier);

        CalibrationReport epss = e.Calibration.Single(c => c.Quantity == "epss-raw");
        Assert.Equal(1, epss.Summary.Count);
        Assert.Equal(0.09, epss.Summary.Brier);

        CalibrationReport reach = e.Calibration.Single(c => c.Quantity == "reach-model");
        Assert.Equal(3, reach.Summary.Count);
        Assert.Equal(0.356667, reach.Summary.Brier);
    }

    [Fact]
    public void The_reach_factor_is_compared_with_the_observed_rate_for_each_label()
    {
        IReadOnlyList<ReachLabelCalibration> rows = BenchEvaluator.Evaluate([CaseA(), CaseB()], 0, 0, 0, 1).ReachByLabel;

        ReachLabelCalibration unreachable = rows.Single(r => r.Label == "unreachable");
        Assert.Equal(1, unreachable.Count);
        Assert.Equal(1.0, unreachable.ObservedReachableRate);
        Assert.Equal(0.1, unreachable.MeanPredictedReach);

        ReachLabelCalibration none = rows.Single(r => r.Label == "not-analyzed");
        Assert.Equal(0, none.Count);
        Assert.Null(none.ObservedReachableRate);
    }

    [Fact]
    public void Intervals_need_at_least_two_cases_with_an_exploited_finding()
    {
        BenchEvaluation single = BenchEvaluator.Evaluate([CaseA(), CaseB()], 0, 0, 100, 1);

        Assert.Equal(0, single.Bootstrap.Iterations);
        Assert.Contains("at least 2 cases", single.Bootstrap.NotComputedReason);
        Assert.All(single.Methods, m => Assert.Null(m.AveragePrecisionCi));
        Assert.All(single.Differences, d => Assert.Null(d.Ci));

        BenchEvaluation off = BenchEvaluator.Evaluate([CaseA(), CaseA()], 0, 0, 0, 1);
        Assert.Contains("switched off", off.Bootstrap.NotComputedReason);
    }

    [Fact]
    public void Intervals_are_deterministic_ordered_and_zero_wide_for_identical_orderings()
    {
        BenchCaseData second = new("c", new[]
        {
            F("C1", 1, 1, true, 8.0, "reachable", true),
            F("C2", 2, 2, false, 6.0, "reachable", false),
        });

        BenchEvaluation first = BenchEvaluator.Evaluate([CaseA(), second], 0, 0, 200, 42);
        BenchEvaluation again = BenchEvaluator.Evaluate([CaseA(), second], 0, 0, 200, 42);

        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(again));
        Assert.Equal(200, first.Bootstrap.Iterations);
        Assert.Null(first.Bootstrap.NotComputedReason);

        Assert.All(first.Methods, m =>
        {
            Assert.NotNull(m.AveragePrecisionCi);
            Assert.True(m.AveragePrecisionCi!.Low <= m.AveragePrecisionCi.High);
        });

        // In case C all methods agree; in case A the risk model and B1 agree: their difference has no spread.
        BenchDifference same = first.Differences.Single(d => d.Versus == BenchEvaluator.B1 && d.Metric == "averagePrecision");
        Assert.Equal(0.0, same.Difference);
        Assert.Equal(new Interval(0.0, 0.0), same.Ci);
    }

    [Fact]
    public void Every_method_has_a_description_and_an_unknown_method_is_refused()
    {
        Assert.All(BenchEvaluator.MethodIds, id => Assert.False(string.IsNullOrWhiteSpace(BenchEvaluator.Describe(id))));
        Assert.Throws<ArgumentOutOfRangeException>(() => BenchEvaluator.Describe("nope"));
        Assert.Throws<ArgumentOutOfRangeException>(() => BenchEvaluator.Present("nope", []));
    }
}

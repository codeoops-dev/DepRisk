using DepRisk.Core.Model;

namespace DepRisk.Core.Bench;

/// <summary>One finding of a benchmark case with the ground truth attached to it. Only labeled findings take part in the metrics.</summary>
public sealed record BenchFinding(
    string Id,
    string PackageId,
    string PackageVersion,
    int BaselineRank,
    int RiskRank,
    double? Cvss,
    string? Severity,
    string? ReachLabel,
    bool Exploited,
    bool? ReachableTruth,
    double ExploitMean,
    double ReachMean,
    double? Epss);

/// <summary>The labeled findings of one case (one project analysis).</summary>
public sealed record BenchCaseData(string Id, IReadOnlyList<BenchFinding> Findings);

public sealed record AtK(int K, double? Recall, double? Precision);

/// <summary>
/// One method over the selected cases. Averages are macro averages over cases (every project counts once). <c>AlertFractionToFullRecall</c> is
/// the share of a case's findings a reader goes through, from the top, to have seen every exploited one; it is averaged over the cases
/// where the method presents all of them (<c>CasesFullRecall</c> of <c>CasesWithPositives</c>), so read it together with <c>ExploitedMissed</c>.
/// </summary>
public sealed record BenchMethodResult(
    string Id,
    string Description,
    int CasesWithPositives,
    int CasesFullRecall,
    int Presented,
    int Suppressed,
    int ExploitedMissed,
    double? AveragePrecision,
    double? AlertFractionToFullRecall,
    IReadOnlyList<AtK> AtK,
    Interval? AveragePrecisionCi,
    Interval? AlertFractionCi);

/// <summary>The paired bootstrap difference <c>method - versus</c> of one metric (same resampled cases for both).</summary>
public sealed record BenchDifference(string Method, string Versus, string Metric, double? Difference, Interval? Ci);

public sealed record BootstrapInfo(int Iterations, string Seed, double Level, string? NotComputedReason);

public sealed record PrecisionRecall(int Predicted, int TruePositives, int TruthPositives, double? Precision, double? Recall);

/// <summary>Analyzer label against ground truth: how many findings with this label were truly reachable and how many were not.</summary>
public sealed record ReachConfusionRow(string Label, int TruthReachable, int TruthNotReachable);

/// <summary>
/// Reachability labels against ground truth, over findings analyzed and labeled. <c>UnsoundUnreachable</c> counts findings the analyzer called
/// <c>unreachable</c> that truly are reachable: the number that decides whether suppressing them is safe. Strict counts only <c>reachable</c> as
/// a positive call, lenient also counts <c>possibly-reachable</c>; <c>unknown</c> is never a positive call but its truth-positives lower recall.
/// </summary>
public sealed record BenchReachEvaluation(
    int Evaluated,
    double? Coverage,
    int UnreachableTotal,
    int UnsoundUnreachable,
    IReadOnlyList<ReachConfusionRow> Rows,
    PrecisionRecall Strict,
    PrecisionRecall Lenient);

/// <summary>For each reachability label (and "not-analyzed"): how often the code was truly reachable against what the model's Reach factor expects. The input of calibrating the Reach priors.</summary>
public sealed record ReachLabelCalibration(string Label, int Count, double? ObservedReachableRate, double? MeanPredictedReach);

public sealed record CalibrationReport(string Quantity, string Predicted, string Outcome, CalibrationSummary Summary);

public sealed record NotEvaluated(string Metric, string Reason);

public sealed record BenchCounts(
    int Cases,
    int CasesWithPositives,
    int Findings,
    int Labeled,
    int Unlabeled,
    int LabelsUnmatched,
    int Exploited,
    int ReachTruthKnown,
    int ReachableTruth);

/// <summary>What the evaluator computes from labeled findings (the part of the result that depends only on the data).</summary>
public sealed record BenchEvaluation(
    BenchCounts Counts,
    IReadOnlyList<BenchMethodResult> Methods,
    IReadOnlyList<BenchDifference> Differences,
    BootstrapInfo Bootstrap,
    BenchReachEvaluation? Reach,
    IReadOnlyList<ReachLabelCalibration> ReachByLabel,
    IReadOnlyList<CalibrationReport> Calibration);

public sealed record BenchDataset(
    string Name,
    string? Description,
    bool Synthetic,
    string Digest,
    string SignalsAsOf,
    string OutcomeFrom,
    string OutcomeTo,
    string LabelSource);

public sealed record BenchModelInfo(int Samples, string Seed, string SeedSource, string RankBy, string Calibration, string ParametersDigest);

/// <summary>
/// Result of <c>deprisk bench</c>. Public contract: schemas/bench-result.v1.schema.json. Deterministic: no timestamps, no absolute paths.
/// </summary>
public sealed record BenchResult(
    int SchemaVersion,
    ToolInfo Tool,
    BenchDataset Dataset,
    string Split,
    BenchModelInfo Model,
    BenchCounts Counts,
    IReadOnlyList<BenchMethodResult> Methods,
    IReadOnlyList<BenchDifference> Differences,
    BootstrapInfo Bootstrap,
    BenchReachEvaluation? Reach,
    IReadOnlyList<ReachLabelCalibration> ReachByLabel,
    IReadOnlyList<CalibrationReport> Calibration,
    IReadOnlyList<NotEvaluated> NotEvaluated,
    IReadOnlyList<string> Warnings)
{
    public const int CurrentSchemaVersion = 1;
}

using System.Globalization;
using DepRisk.Core;
using DepRisk.Core.Bench;
using DepRisk.Core.Model;
using DepRisk.Core.Risk;
using DepRisk.Data.Reach;
using DepRisk.Data.Risk;

namespace DepRisk.Data.Bench;

public sealed record BenchCalibrationOptions(
    LoadedBenchManifest Manifest,
    LoadedRiskParameters Start,
    ReachPrior Prior,
    int MinCount,
    bool Strict,
    string? AnalyzerPath,
    TimeSpan ReachTimeout,
    string WorkingDirectory);

public sealed record BenchCalibrationOutcome(
    BenchDataset Dataset,
    int Cases,
    int Observations,
    ReachFit Fit,
    RiskParameters Parameters,
    string Provenance,
    IReadOnlyList<string> Warnings,
    string InputsDigest);

/// <summary>
/// <c>deprisk bench calibrate</c>: fits the Reach factor of the risk model on the <b>development</b> split only, so that the result can
/// be judged on the held-out split (<c>deprisk bench --split test --risk-params ...</c>). The analysis runs without EPSS, KEV, and the
/// risk model: the fit uses nothing but the reachability label of each finding and its ground truth.
/// </summary>
public static class BenchCalibrationService
{
    public const string SplitUsed = "dev";

    public static BenchCalibrationOutcome Run(
        BenchCalibrationOptions options,
        ToolInfo tool,
        IAnalyzerProcess analyzer,
        Func<string, string?> getEnvironmentVariable)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(tool);

        BenchManifest manifest = options.Manifest.Manifest;
        List<BenchCase> cases = manifest.Cases.Where(c => c.Split == SplitUsed).ToList();

        if (cases.Count == 0)
        {
            throw new InvalidInputException($"the benchmark has no case in the '{SplitUsed}' split; the Reach factor is fitted on that split only.");
        }

        List<(string Label, bool Truth)> observations = [];
        System.Text.StringBuilder digest = new();
        digest.Append("bench-calibrate:").Append(options.Manifest.Digest).Append("\nstart:").Append(options.Start.ParametersDigest)
            .Append("\nprior:").Append(options.Prior).Append("\nmin:").Append(options.MinCount.ToString(CultureInfo.InvariantCulture)).Append('\n');

        int unlabeled = 0;
        int unmatched = 0;

        foreach (BenchCase item in cases)
        {
            RankPipelineOutcome outcome = RankPipeline.Run(
                BenchService.PipelineOptions(item, options.Strict, options.AnalyzerPath, options.ReachTimeout, options.WorkingDirectory, withSignals: false, risk: null),
                tool,
                analyzer,
                getEnvironmentVariable,
                options.WorkingDirectory);

            (List<(RankedFinding Finding, BenchLabel Label)> pairs, int caseUnlabeled, int caseUnmatched) = BenchService.JoinLabels(item, outcome.Ranking.Result);
            unlabeled += caseUnlabeled;
            unmatched += caseUnmatched;

            foreach ((RankedFinding finding, BenchLabel label) in pairs)
            {
                if (label.Reachable is { } truth)
                {
                    observations.Add((finding.Reachability?.Label ?? ReachCalibration.NotAnalyzed, truth));
                }
            }

            digest.Append(item.Id).Append('|').Append(outcome.Ranking.InputsDigest).Append('\n');
        }

        if (options.Strict && (unlabeled > 0 || unmatched > 0))
        {
            throw new InvalidInputException(
                $"--strict: {unlabeled} finding(s) have no label and {unmatched} label(s) match no finding. Fix the labels or the data, or run without --strict.");
        }

        ReachFit fit = ReachCalibration.Fit(observations, options.Start.Parameters.Reach, options.Prior, options.MinCount);

        if (!fit.Labels.Any(l => l.Fitted))
        {
            throw new InvalidInputException(
                $"nothing to fit: no reachability label has {options.MinCount} or more findings with a known truth in the '{SplitUsed}' split ({observations.Count} findings with a known truth in total). Add labels, or lower --min-count.");
        }

        RiskParameters parameters = options.Start.Parameters with { Reach = fit.Reach };

        if (parameters.Validate() is { } problem)
        {
            throw new InvalidInputException($"the fitted parameters are not usable: {problem}.");
        }

        List<string> warnings = [];

        if (manifest.Synthetic)
        {
            warnings.Add("This dataset is synthetic (fixtures for tests): the fitted numbers are not evidence and must not be used.");
        }

        if (unlabeled > 0)
        {
            warnings.Add($"{unlabeled} finding(s) have no label and were not used.");
        }

        if (unmatched > 0)
        {
            warnings.Add($"{unmatched} label(s) match no finding.");
        }

        BenchDataset dataset = new(
            manifest.Name,
            manifest.Description,
            manifest.Synthetic,
            options.Manifest.Digest,
            manifest.SignalsAsOf.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            manifest.OutcomeFrom.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            manifest.OutcomeTo.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            manifest.LabelSource);

        string provenance = Provenance(dataset, cases.Count, observations.Count, options, fit);

        return new BenchCalibrationOutcome(dataset, cases.Count, observations.Count, fit, parameters, provenance, warnings, Digest.Sha256Hex(digest.ToString()));
    }

    private static string Provenance(BenchDataset dataset, int cases, int observations, BenchCalibrationOptions options, ReachFit fit)
    {
        string fitted = string.Join(", ", fit.Labels.Where(l => l.Fitted).Select(l => $"{l.Label} {l.TrulyReachable}/{l.Count}"));
        string kept = string.Join(", ", fit.Labels.Where(l => !l.Fitted).Select(l => l.Label));
        string prior = options.Prior == ReachPrior.Uniform ? "uniform Beta(1, 1) prior" : "the starting parameters as prior";
        string name = dataset.Name.Length > 60 ? dataset.Name[..60] : dataset.Name;

        string text = $"Reach fitted by 'deprisk bench calibrate' on the {SplitUsed} split ({cases} case(s), {observations} findings with a known truth) of '{name}' "
            + $"(manifest {dataset.Digest[..12]}{(dataset.Synthetic ? ", SYNTHETIC: not evidence" : string.Empty)}); {prior}; minimum {options.MinCount} per label. "
            + $"Truly reachable/total per fitted label: {fitted}. Kept as before: {(kept.Length == 0 ? "none" : kept)}. Exploit and Impact are not fitted.";

        return text.Length <= RiskParametersWriter.MaxProvenanceLength ? text : text[..(RiskParametersWriter.MaxProvenanceLength - 1)] + "…";
    }
}

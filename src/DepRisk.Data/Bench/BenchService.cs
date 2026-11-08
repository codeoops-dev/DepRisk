using System.Globalization;
using System.Text;
using DepRisk.Core;
using DepRisk.Core.Bench;
using DepRisk.Core.Model;
using DepRisk.Data.Reach;

namespace DepRisk.Data.Bench;

public sealed record BenchOptions(
    LoadedBenchManifest Manifest,
    string Split,
    RiskRequest Risk,
    bool Strict,
    int BootstrapIterations,
    string? AnalyzerPath,
    TimeSpan ReachTimeout,
    string WorkingDirectory);

public sealed record BenchOutcome(BenchResult Result, string InputsDigest);

/// <summary>
/// <c>deprisk bench</c>: runs the product's own analysis (<see cref="RankPipeline"/>, with the uncertainty model) on every case of the
/// selected split, joins the findings to the ground truth, and lets <see cref="BenchEvaluator"/> compare the methods. Offline, deterministic.
/// </summary>
public static class BenchService
{
    public static readonly IReadOnlyList<string> Splits = ["dev", "test", "all"];

    public static BenchOutcome Run(
        BenchOptions options,
        ToolInfo tool,
        IAnalyzerProcess analyzer,
        Func<string, string?> getEnvironmentVariable)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(tool);

        BenchManifest manifest = options.Manifest.Manifest;

        List<BenchCase> selected = manifest.Cases
            .Where(c => options.Split == "all" || c.Split == options.Split)
            .ToList();

        if (selected.Count == 0)
        {
            throw new InvalidInputException($"the benchmark has no case in the split '{options.Split}'.");
        }

        List<BenchCaseData> data = [];
        StringBuilder digest = new();
        digest.Append("bench:").Append(options.Manifest.Digest).Append("\nsplit:").Append(options.Split).Append('\n');

        int unlabeled = 0;
        int unmatched = 0;
        int casesWithoutReach = 0;
        RiskModelInfo? model = null;

        foreach (BenchCase item in selected)
        {
            RankPipelineOptions pipelineOptions = PipelineOptions(
                item,
                options.Strict,
                options.AnalyzerPath,
                options.ReachTimeout,
                options.WorkingDirectory,
                withSignals: true,
                options.Risk);

            RankPipelineOutcome outcome = RankPipeline.Run(pipelineOptions, tool, analyzer, getEnvironmentVariable, options.WorkingDirectory);
            RankingResult ranking = outcome.Ranking.Result;

            CheckSignalDates(item, ranking, manifest.SignalsAsOf);

            model ??= ranking.Model;

            if (item.SymbolsPath is null)
            {
                casesWithoutReach++;
            }

            (BenchCaseData caseData, int caseUnlabeled, int caseUnmatched) = Join(item, ranking);
            data.Add(caseData);
            unlabeled += caseUnlabeled;
            unmatched += caseUnmatched;
            digest.Append(item.Id).Append('|').Append(outcome.Ranking.InputsDigest).Append('\n');
        }

        if (options.Strict && (unlabeled > 0 || unmatched > 0))
        {
            throw new InvalidInputException(
                $"--strict: {unlabeled} finding(s) have no label and {unmatched} label(s) match no finding. Fix the labels or the data, or run without --strict.");
        }

        if (model is null)
        {
            throw new InvalidOperationException("the risk model was requested but no result carries it.");
        }

        ulong seed = ulong.Parse(model.Seed, CultureInfo.InvariantCulture);
        BenchEvaluation evaluation = BenchEvaluator.Evaluate(data, unlabeled, unmatched, options.BootstrapIterations, seed);

        List<string> warnings = [];

        if (manifest.Synthetic)
        {
            warnings.Add("This dataset is synthetic (fixtures for tests): its numbers are not evidence about any method.");
        }

        if (options.Split == "test")
        {
            warnings.Add("Test split: it is for the final report only. Fitting or tuning on it invalidates the result; use 'dev' for that.");
        }
        else if (options.Split == "all")
        {
            warnings.Add("All cases are used: this mixes the development and the held-out split, so it is not a held-out result.");
        }

        if (options.Split != "test"
            && options.Risk.Parameters.Provenance is { } note
            && note.Contains($"(manifest {options.Manifest.Digest[..12]}", StringComparison.Ordinal))
        {
            warnings.Add("These risk parameters were fitted on the dev split of this very dataset: results on 'dev' or 'all' are not held-out. Evaluate with --split test.");
        }

        if (unlabeled > 0)
        {
            warnings.Add($"{unlabeled} finding(s) have no label and are left out of every metric.");
        }

        if (unmatched > 0)
        {
            warnings.Add($"{unmatched} label(s) match no finding (the data and the labels may have drifted apart).");
        }

        if (casesWithoutReach > 0)
        {
            warnings.Add($"{casesWithoutReach} case(s) have no symbol maps: no reachability verdict exists for them, so B3 keeps their findings and the model uses its not-analyzed prior.");
        }

        BenchResult result = new(
            BenchResult.CurrentSchemaVersion,
            tool,
            new BenchDataset(
                manifest.Name,
                manifest.Description,
                manifest.Synthetic,
                options.Manifest.Digest,
                manifest.SignalsAsOf.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                manifest.OutcomeFrom.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                manifest.OutcomeTo.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                manifest.LabelSource),
            options.Split,
            new BenchModelInfo(model.Samples, model.Seed, model.SeedSource, model.RankBy, model.Calibration, model.ParametersDigest),
            evaluation.Counts,
            evaluation.Methods,
            evaluation.Differences,
            evaluation.Bootstrap,
            evaluation.Reach,
            evaluation.ReachByLabel,
            evaluation.Calibration,
            NotEvaluatedMetrics,
            warnings);

        return new BenchOutcome(result, Digest.Sha256Hex(digest.ToString()));
    }

    /// <summary>
    /// The analysis options of one case. <paramref name="withSignals"/> false leaves EPSS and KEV out (calibrating the Reach priors does
    /// not use them), <paramref name="risk"/> null skips the risk model.
    /// </summary>
    internal static RankPipelineOptions PipelineOptions(
        BenchCase item,
        bool strict,
        string? analyzerPath,
        TimeSpan timeout,
        string workingDirectory,
        bool withSignals,
        RiskRequest? risk) =>
        new(
            item.ScanPath,
            item.AdvisoriesPath,
            withSignals ? item.EpssPath : null,
            withSignals ? item.KevPath : null,
            item.Ecosystem,
            strict,
            item.SymbolsPath is null
                ? null
                : new ReachOptions(
                    item.ScanPath,
                    item.AdvisoriesPath,
                    item.SymbolsPath,
                    item.SourcePath,
                    item.Ecosystem,
                    strict,
                    item.EntrypointMode,
                    item.Entrypoints,
                    analyzerPath,
                    timeout,
                    workingDirectory),
            risk);

    public static readonly IReadOnlyList<NotEvaluated> NotEvaluatedMetrics =
    [
        new("baseline-b4-upgrade-everything", "needs the remediation planner (v0.3)"),
        new("residual-expected-risk-vs-effort", "needs the remediation planner and the effort model (v0.3)"),
        new("post-plan-build-test-pass-rate", "needs the remediation planner (v0.3)"),
        new("plan-verification-time", "needs the verified kernel (v0.4)"),
        new("quantile-calibration-of-loss", "public ground truth records events (exploited, reachable), not losses; the probabilities behind the loss (Reach, Exploit) are calibrated instead"),
    ];

    /// <summary>
    /// The leakage guard: the signals a case is analyzed with must not be newer than the date the manifest says they were fixed at,
    /// because EPSS and KEV published after that date can contain the outcome that is being predicted. A signal file whose date cannot
    /// be read is refused for the same reason.
    /// </summary>
    private static void CheckSignalDates(BenchCase item, RankingResult ranking, DateOnly asOf)
    {
        Check(item, "EPSS", item.EpssPath is null ? null : ranking.Signals.Epss, asOf);
        Check(item, "KEV", item.KevPath is null ? null : ranking.Signals.Kev, asOf);
    }

    private static void Check(BenchCase item, string name, SignalSourceInfo? info, DateOnly asOf)
    {
        if (info is null)
        {
            return;
        }

        string text = info.Date ?? string.Empty;

        if (text.Length < 10 || !DateOnly.TryParseExact(text[..10], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly published))
        {
            throw new InvalidInputException(
                $"case '{item.Id}': the {name} data carries no readable publication date, so it cannot be shown to predate signalsAsOf ({asOf:yyyy-MM-dd}); refused (leakage guard).");
        }

        if (published > asOf)
        {
            throw new InvalidInputException(
                $"case '{item.Id}': the {name} data is dated {published:yyyy-MM-dd}, after signalsAsOf ({asOf:yyyy-MM-dd}); it could contain the outcomes being predicted (leakage guard).");
        }
    }

    private static (BenchCaseData Data, int Unlabeled, int Unmatched) Join(BenchCase item, RankingResult ranking)
    {
        (List<(RankedFinding Finding, BenchLabel Label)> pairs, int unlabeled, int unmatched) = JoinLabels(item, ranking);
        List<BenchFinding> findings = [];

        foreach ((RankedFinding f, BenchLabel found) in pairs)
        {
            FindingRisk risk = f.Risk ?? throw new InvalidOperationException("a finding has no risk distribution although the model was requested.");

            findings.Add(new BenchFinding(
                f.Id,
                f.Package.Id,
                f.Package.Version,
                f.BaselineRank ?? f.Rank,
                f.Rank,
                f.Signals.Cvss?.BaseScore,
                f.Severity,
                f.Reachability?.Label,
                found.Exploited,
                found.Reachable,
                risk.ExploitMean,
                risk.ReachMean,
                f.Signals.Epss?.Probability));
        }

        return (new BenchCaseData(item.Id, findings), unlabeled, unmatched);
    }

    /// <summary>Joins the findings of a case to its labels (by advisory id or alias, and package id); counts what matched nothing on either side.</summary>
    internal static (List<(RankedFinding Finding, BenchLabel Label)> Pairs, int Unlabeled, int Unmatched) JoinLabels(BenchCase item, RankingResult ranking)
    {
        Dictionary<string, BenchLabel> byKey = new(StringComparer.OrdinalIgnoreCase);

        foreach (BenchLabel label in item.Labels)
        {
            byKey[Key(label.Advisory, label.Package)] = label;
        }

        HashSet<string> used = new(StringComparer.OrdinalIgnoreCase);
        List<(RankedFinding, BenchLabel)> pairs = [];
        int unlabeled = 0;

        foreach (RankedFinding f in ranking.Findings)
        {
            BenchLabel? found = null;

            foreach (string candidate in f.Aliases.Prepend(f.Id))
            {
                string key = Key(candidate, f.Package.Id);

                if (!byKey.TryGetValue(key, out BenchLabel? label))
                {
                    continue;
                }

                if (found is not null && !ReferenceEquals(found, label))
                {
                    throw new InvalidInputException(
                        $"case '{item.Id}': the finding {SafeText.Clean(f.Id, 60)} in {SafeText.Clean(f.Package.Id, 60)} matches two different labels (by its id and by an alias); keep one.");
                }

                found = label;
                used.Add(key);
            }

            if (found is null)
            {
                unlabeled++;
                continue;
            }

            pairs.Add((f, found));
        }

        return (pairs, unlabeled, byKey.Count - used.Count);
    }

    private static string Key(string advisory, string package) => advisory + "\u001f" + package;
}

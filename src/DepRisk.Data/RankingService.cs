using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Ranking;
using DepRisk.Core.Reach;
using DepRisk.Core.Risk;
using DepRisk.Core.Signals;
using DepRisk.Data.Risk;
using DepRisk.Data.Signals;

namespace DepRisk.Data;

/// <summary>A ranking result plus the digest of everything read to produce it, and the loaded data's diagnostics.</summary>
public sealed record RankingOutcome(RankingResult Result, string InputsDigest, FindingsOutcome Findings, EpssData? Epss, KevData? Kev);

/// <summary>Matches findings (see <see cref="FindingsService"/>) and orders them with the baseline ranking.</summary>
public static class RankingService
{
    public static RankingOutcome Rank(
        string scanPath,
        string advisoriesPath,
        string? epssPath,
        string? kevPath,
        ToolInfo tool,
        bool strict,
        Ecosystem? ecosystem = null,
        FindingsOutcome? matched = null)
    {
        ArgumentNullException.ThrowIfNull(scanPath);
        ArgumentNullException.ThrowIfNull(advisoriesPath);
        ArgumentNullException.ThrowIfNull(tool);

        // The findings may already have been computed (for example by the reach analysis, which matches first).
        FindingsOutcome findings = matched ?? FindingsService.Match(scanPath, advisoriesPath, tool, strict, ecosystem);
        EpssData? epss = epssPath is null ? null : EpssLoader.Load(epssPath);
        KevData? kev = kevPath is null ? null : KevLoader.Load(kevPath);

        if (strict)
        {
            if (epss is { SkippedRows: > 0 })
            {
                throw new InvalidInputException($"{epss.SkippedRows} EPSS row(s) are invalid and --strict was given. First: {epss.SkippedSamples[0]}");
            }

            if (kev is { SkippedEntries: > 0 })
            {
                throw new InvalidInputException($"{kev.SkippedEntries} KEV entr(ies) are invalid and --strict was given. First: {kev.SkippedSamples[0]}");
            }
        }

        RankingResult result = Compute(findings.Result, epss, kev, tool);

        string inputsDigest = Digest.Sha256Hex(
            findings.InputsDigest + "\n" + (epss?.Digest ?? "-") + "\n" + (kev?.Digest ?? "-") + "\n");

        return new RankingOutcome(result, inputsDigest, findings, epss, kev);
    }

    /// <summary>
    /// Adds the reachability verdicts to a ranking. The order and the ranks do not change: reachability is information here
    /// (and for the policy gate); it is not part of the baseline method. A finding without a verdict stays "not analyzed".
    /// </summary>
    public static RankingResult WithReachability(RankingResult ranking, ReachabilityResult reach)
    {
        ArgumentNullException.ThrowIfNull(ranking);
        ArgumentNullException.ThrowIfNull(reach);

        Dictionary<(string, string, string), ReachVerdict> verdicts = new();

        foreach (ReachFinding item in reach.Findings)
        {
            Finding f = item.Finding;
            verdicts[(f.Id.ToUpperInvariant(), f.Package.Id.ToUpperInvariant(), f.Package.Version)] = item.Reachability;
        }

        List<RankedFinding> withReach = ranking.Findings
            .Select(r => verdicts.TryGetValue((r.Id.ToUpperInvariant(), r.Package.Id.ToUpperInvariant(), r.Package.Version), out ReachVerdict? v)
                ? r with { Reachability = new FindingReach(v.Label, v.Reason, v.Symbol) }
                : r)
            .ToList();

        return ranking with { Findings = withReach, Reach = new RankReachInfo(reach.Analyzer, reach.SymbolMaps, reach.Source, reach.Summary) };
    }

    /// <summary>
    /// Replaces the baseline order by the order of the risk model (seeded Monte Carlo over Reach x Exploit x Impact). Reachability, if
    /// present, is an input of the model. Without a seed, one is derived from the parameters and the number of samples only, so that a
    /// finding's numbers do not change when unrelated findings appear or disappear.
    /// </summary>
    public static RankingResult WithRiskModel(RankingResult ranking, LoadedRiskParameters parameters, int samples, ulong? seed, string rankBy)
    {
        ArgumentNullException.ThrowIfNull(ranking);
        ArgumentNullException.ThrowIfNull(parameters);

        ulong effectiveSeed = seed ?? DefaultSeed(parameters.ParametersDigest, samples);
        IReadOnlyList<RankedFinding> ranked = RiskRanker.Rank(ranking.Findings, parameters.Parameters, effectiveSeed, samples, rankBy);

        return ranking with
        {
            Method = RankingResult.RiskMethod,
            Ordering = [$"risk.{rankBy}", "baseline-rank"],
            Findings = ranked,
            Model = new RiskModelInfo(
                samples,
                effectiveSeed.ToString(System.Globalization.CultureInfo.InvariantCulture),
                seed is null ? "default" : "given",
                rankBy,
                parameters.Calibration,
                parameters.ParametersDigest,
                parameters.Parameters),
        };
    }

    /// <summary>The seed used when none is given: a function of the parameters and the sample count, nothing else.</summary>
    public static ulong DefaultSeed(string parametersDigest, int samples) =>
        BitConverter.ToUInt64(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"deprisk/risk/v1|{parametersDigest}|{samples}")), 0);

    /// <summary>Pure ranking of an already-computed findings result.</summary>
    public static RankingResult Compute(FindingsResult findings, EpssData? epss, KevData? kev, ToolInfo tool)
    {
        IReadOnlyList<RankedFinding> ranked = BaselineRanker.Rank(findings.Findings, epss, kev);

        SignalSourceInfo? epssInfo = epss is null
            ? null
            : new SignalSourceInfo(epss.Source, epss.Digest, epss.ModelVersion, epss.ScoreDate, epss.Scores.Count, epss.SkippedRows);

        SignalSourceInfo? kevInfo = kev is null
            ? null
            : new SignalSourceInfo(kev.Source, kev.Digest, kev.CatalogVersion, kev.DateReleased, kev.Entries.Count, kev.SkippedEntries);

        return new RankingResult(
            RankingResult.CurrentSchemaVersion,
            tool,
            findings.Ecosystem,
            RankingResult.BaselineMethod,
            RankingResult.BaselineOrdering,
            findings.Advisories,
            new SignalSources(epssInfo, kevInfo),
            findings.ProjectsScanned,
            findings.PackagesScanned,
            findings.PackagesSkipped,
            ranked);
    }
}

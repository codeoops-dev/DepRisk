using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Ranking;
using DepRisk.Core.Signals;
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
        bool strict)
    {
        ArgumentNullException.ThrowIfNull(scanPath);
        ArgumentNullException.ThrowIfNull(advisoriesPath);
        ArgumentNullException.ThrowIfNull(tool);

        FindingsOutcome findings = FindingsService.Match(scanPath, advisoriesPath, tool, strict);
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

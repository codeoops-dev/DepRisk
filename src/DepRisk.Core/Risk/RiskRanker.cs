using DepRisk.Core.Model;

namespace DepRisk.Core.Risk;

/// <summary>Orders findings by a statistic of their risk distribution.</summary>
public static class RiskRanker
{
    public static readonly IReadOnlyList<string> Statistics = ["mean", "p50", "p90", "p95", "cvar95"];

    public static double Statistic(FindingRisk risk, string rankBy) => rankBy switch
    {
        "mean" => risk.Mean,
        "p50" => risk.P50,
        "p90" => risk.P90,
        "p95" => risk.P95,
        "cvar95" => risk.Cvar95,
        _ => throw new ArgumentOutOfRangeException(nameof(rankBy), $"unknown statistic '{rankBy}'"),
    };

    /// <summary>The statistic named on the command line: "cvar" is accepted for "cvar95".</summary>
    public static string? NormalizeStatistic(string? name) => name switch
    {
        "cvar" => "cvar95",
        _ when name is not null && Statistics.Contains(name) => name,
        _ => null,
    };

    public static RiskInput InputFor(RankedFinding finding) => new(
        $"{finding.Id}|{finding.Package.Id}|{finding.Package.Version}",
        finding.Reachability?.Label,
        finding.Signals.Epss?.Probability,
        finding.Signals.Kev is not null,
        finding.Signals.Kev?.KnownRansomwareUse ?? false,
        finding.Signals.Cvss?.BaseScore,
        finding.Severity);

    /// <summary>
    /// Ranks the (baseline-ranked) findings by <paramref name="rankBy"/>, highest risk first; ties keep the baseline order. The
    /// result carries the distribution, the new rank, and the rank the baseline gave.
    /// </summary>
    public static IReadOnlyList<RankedFinding> Rank(IReadOnlyList<RankedFinding> baseline, RiskParameters parameters, ulong seed, int samples, string rankBy)
    {
        ArgumentNullException.ThrowIfNull(baseline);

        IReadOnlyList<RiskDistribution> distributions = RiskModel.Evaluate(baseline.Select(InputFor).ToList(), parameters, seed, samples);

        return baseline
            .Select((f, i) => f with
            {
                Risk = new FindingRisk(
                    Round(distributions[i].Mean),
                    Round(distributions[i].P50),
                    Round(distributions[i].P90),
                    Round(distributions[i].P95),
                    Round(distributions[i].Cvar95),
                    Round(distributions[i].ReachMean),
                    Round(distributions[i].ExploitMean),
                    Round(distributions[i].ImpactMean)),
                BaselineRank = f.Rank,
            })
            .OrderByDescending(f => Statistic(f.Risk!, rankBy))
            .ThenBy(f => f.BaselineRank)
            .Select((f, i) => f with { Rank = i + 1 })
            .ToList();
    }

    /// <summary>Results are reported to six decimals: more digits would only show last-bit differences between platforms.</summary>
    private static double Round(double value) => Math.Round(value, 6, MidpointRounding.ToEven);
}

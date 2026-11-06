using System.Globalization;

namespace DepRisk.Core.Risk;

/// <summary>A Beta(alpha, beta) distribution on [0, 1]; both parameters must be positive.</summary>
public sealed record BetaParams(double Alpha, double Beta)
{
    public double Mean => Alpha / (Alpha + Beta);
}

/// <summary>Reach_a: the probability that the vulnerable code is exercised, by reachability label (docs/method.md, section 4).</summary>
public sealed record ReachParams(
    BetaParams Reachable,
    BetaParams PossiblyReachable,
    BetaParams Unknown,
    BetaParams Unreachable,
    BetaParams NotAnalyzed);

/// <summary>
/// Exploit_a: the probability of exploitation. With an EPSS value p it is Beta(p k, (1 - p) k), k = <c>EpssConcentration</c>; without
/// one it is <c>NoEpss</c>. A finding in the CISA KEV catalog has its mean raised to at least <c>KevMean</c> (ransomware use:
/// <c>RansomwareKevMean</c>) with concentration <c>KevConcentration</c>.
/// </summary>
public sealed record ExploitParams(
    double EpssConcentration,
    BetaParams NoEpss,
    double KevMean,
    double RansomwareKevMean,
    double KevConcentration);

/// <summary>
/// Impact_a: Uniform(<c>Low</c>, <c>High</c>) (the asset-criticality range) times a severity factor: CVSS base score / 10 if known,
/// else a point factor for the database rating, else Uniform(<c>UnknownSeverityLow</c>, <c>UnknownSeverityHigh</c>).
/// </summary>
public sealed record ImpactParams(
    double Low,
    double High,
    double LowSeverityFactor,
    double ModerateSeverityFactor,
    double HighSeverityFactor,
    double CriticalSeverityFactor,
    double UnknownSeverityLow,
    double UnknownSeverityHigh);

/// <summary>
/// The parameters of the risk model. <see cref="Default"/> holds placeholders that are NOT calibrated: docs/method.md leaves the
/// calibration to the benchmark, and every result that uses them says so. They exist so that the model runs, can be inspected, and
/// can be replaced (<c>--risk-params</c>).
/// </summary>
public sealed record RiskParameters(ReachParams Reach, ExploitParams Exploit, ImpactParams Impact)
{
    public static RiskParameters Default { get; } = new(
        new ReachParams(
            Reachable: new BetaParams(9, 1),
            PossiblyReachable: new BetaParams(4, 2),
            Unknown: new BetaParams(2, 2),
            Unreachable: new BetaParams(1, 49),
            NotAnalyzed: new BetaParams(2, 2)),
        new ExploitParams(
            EpssConcentration: 20,
            NoEpss: new BetaParams(0.5, 9.5),
            KevMean: 0.7,
            RansomwareKevMean: 0.85,
            KevConcentration: 10),
        new ImpactParams(
            Low: 3,
            High: 6,
            LowSeverityFactor: 0.2,
            ModerateSeverityFactor: 0.5,
            HighSeverityFactor: 0.75,
            CriticalSeverityFactor: 0.95,
            UnknownSeverityLow: 0.1,
            UnknownSeverityHigh: 1.0));

    /// <summary>Returns the first problem, or null if every parameter is usable.</summary>
    public string? Validate()
    {
        foreach ((string name, BetaParams beta) in BetaParameters())
        {
            if (!(beta.Alpha > 0 && beta.Beta > 0 && double.IsFinite(beta.Alpha) && double.IsFinite(beta.Beta) && beta.Alpha <= 1e6 && beta.Beta <= 1e6))
            {
                return $"{name}: alpha and beta must be finite numbers above 0 (and at most 1000000)";
            }
        }

        if (!IsFiniteIn(Exploit.EpssConcentration, 0.1, 1e6) || !IsFiniteIn(Exploit.KevConcentration, 0.1, 1e6))
        {
            return "exploit: concentrations must be between 0.1 and 1000000";
        }

        if (!IsFiniteIn(Exploit.KevMean, 0.001, 0.999) || !IsFiniteIn(Exploit.RansomwareKevMean, 0.001, 0.999))
        {
            return "exploit: KEV means must be between 0.001 and 0.999";
        }

        ImpactParams i = Impact;

        if (!IsFiniteIn(i.Low, 0, 1000) || !IsFiniteIn(i.High, 0, 1000) || i.Low > i.High)
        {
            return "impact: low and high must be between 0 and 1000, with low <= high";
        }

        double[] factors = [i.LowSeverityFactor, i.ModerateSeverityFactor, i.HighSeverityFactor, i.CriticalSeverityFactor, i.UnknownSeverityLow, i.UnknownSeverityHigh];

        if (factors.Any(f => !IsFiniteIn(f, 0, 1)) || i.UnknownSeverityLow > i.UnknownSeverityHigh)
        {
            return "impact: severity factors must be between 0 and 1 (unknown low <= unknown high)";
        }

        return null;
    }

    /// <summary>A canonical text of every parameter (invariant culture, round-trip numbers), for digests.</summary>
    public string Canonical()
    {
        string N(double d) => d.ToString("R", CultureInfo.InvariantCulture);
        string B(BetaParams b) => $"{N(b.Alpha)},{N(b.Beta)}";

        return string.Join(
            ';',
            $"reach.reachable={B(Reach.Reachable)}",
            $"reach.possiblyReachable={B(Reach.PossiblyReachable)}",
            $"reach.unknown={B(Reach.Unknown)}",
            $"reach.unreachable={B(Reach.Unreachable)}",
            $"reach.notAnalyzed={B(Reach.NotAnalyzed)}",
            $"exploit.epssConcentration={N(Exploit.EpssConcentration)}",
            $"exploit.noEpss={B(Exploit.NoEpss)}",
            $"exploit.kevMean={N(Exploit.KevMean)}",
            $"exploit.ransomwareKevMean={N(Exploit.RansomwareKevMean)}",
            $"exploit.kevConcentration={N(Exploit.KevConcentration)}",
            $"impact={N(Impact.Low)},{N(Impact.High)},{N(Impact.LowSeverityFactor)},{N(Impact.ModerateSeverityFactor)},{N(Impact.HighSeverityFactor)},{N(Impact.CriticalSeverityFactor)},{N(Impact.UnknownSeverityLow)},{N(Impact.UnknownSeverityHigh)}");
    }

    private IEnumerable<(string, BetaParams)> BetaParameters()
    {
        yield return ("reach.reachable", Reach.Reachable);
        yield return ("reach.possiblyReachable", Reach.PossiblyReachable);
        yield return ("reach.unknown", Reach.Unknown);
        yield return ("reach.unreachable", Reach.Unreachable);
        yield return ("reach.notAnalyzed", Reach.NotAnalyzed);
        yield return ("exploit.noEpss", Exploit.NoEpss);
    }

    private static bool IsFiniteIn(double value, double min, double max) => double.IsFinite(value) && value >= min && value <= max;
}

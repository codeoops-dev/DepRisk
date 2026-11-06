using DepRisk.Core.Reach;

namespace DepRisk.Core.Risk;

/// <summary>What the model needs to know about one finding.</summary>
public sealed record RiskInput(
    string Key,
    string? ReachLabel,
    double? EpssProbability,
    bool InKev,
    bool KnownRansomwareUse,
    double? CvssBaseScore,
    string? DatabaseSeverity);

/// <summary>The distribution of R = Reach x Exploit x Impact for one finding over the Monte Carlo scenarios.</summary>
public sealed record RiskDistribution(
    double Mean,
    double P50,
    double P90,
    double P95,
    double Cvar95,
    double ReachMean,
    double ExploitMean,
    double ImpactMean);

/// <summary>
/// The risk model of docs/method.md section 4: for every finding, <c>R = Reach x Exploit x Impact</c> with each factor a random
/// variable, sampled with a seeded generator. Each finding has its own random stream (derived from the seed and the finding's key),
/// so the numbers of a finding do not depend on which other findings are present or in what order. Independence between the factors
/// and between findings is assumed (a known simplification, listed as a research question).
/// </summary>
public static class RiskModel
{
    public const int MinSamples = 100;
    public const int MaxSamples = 200_000;
    public const long MaxTotalDraws = 100_000_000;

    public static IReadOnlyList<RiskDistribution> Evaluate(IReadOnlyList<RiskInput> inputs, RiskParameters parameters, ulong seed, int samples)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(parameters);

        if (parameters.Validate() is { } problem)
        {
            throw new ArgumentException(problem, nameof(parameters));
        }

        if (samples is < MinSamples or > MaxSamples)
        {
            throw new ArgumentOutOfRangeException(nameof(samples), $"samples must be between {MinSamples} and {MaxSamples}.");
        }

        if ((long)inputs.Count * samples > MaxTotalDraws)
        {
            throw new ArgumentOutOfRangeException(nameof(samples), $"{inputs.Count} findings x {samples} samples is more than {MaxTotalDraws} scenarios; use fewer samples.");
        }

        return inputs.Select(input => EvaluateOne(input, parameters, seed, samples)).ToList();
    }

    private static RiskDistribution EvaluateOne(RiskInput input, RiskParameters p, ulong seed, int samples)
    {
        Prng random = new(Prng.StreamSeed(seed, input.Key.ToUpperInvariant()));
        BetaParams reach = ReachFor(input.ReachLabel, p.Reach);
        BetaParams exploit = ExploitFor(input, p.Exploit);
        (double impactLow, double impactHigh) = (p.Impact.Low, p.Impact.High);

        double[] risk = new double[samples];
        double reachSum = 0;
        double exploitSum = 0;
        double impactSum = 0;

        for (int s = 0; s < samples; s++)
        {
            double r = random.NextBeta(reach.Alpha, reach.Beta);
            double e = random.NextBeta(exploit.Alpha, exploit.Beta);
            double scale = impactLow + ((impactHigh - impactLow) * random.NextOpenUnit());
            double impact = scale * SeverityFactor(input, p.Impact, random);

            risk[s] = r * e * impact;
            reachSum += r;
            exploitSum += e;
            impactSum += impact;
        }

        Array.Sort(risk);

        return new RiskDistribution(
            Mean: risk.Sum() / samples,
            P50: Quantile(risk, 0.50),
            P90: Quantile(risk, 0.90),
            P95: Quantile(risk, 0.95),
            Cvar95: TailMean(risk, 0.95),
            ReachMean: reachSum / samples,
            ExploitMean: exploitSum / samples,
            ImpactMean: impactSum / samples);
    }

    public static BetaParams ReachFor(string? label, ReachParams p) => label switch
    {
        ReachLabels.Reachable => p.Reachable,
        ReachLabels.PossiblyReachable => p.PossiblyReachable,
        ReachLabels.Unknown => p.Unknown,
        ReachLabels.Unreachable => p.Unreachable,
        _ => p.NotAnalyzed,
    };

    public static BetaParams ExploitFor(RiskInput input, ExploitParams p)
    {
        double? epss = input.EpssProbability is { } e ? Math.Clamp(e, 0.001, 0.999) : null;

        if (input.InKev)
        {
            double floor = input.KnownRansomwareUse ? p.RansomwareKevMean : p.KevMean;
            double mean = Math.Max(epss ?? 0.0, floor);
            return new BetaParams(mean * p.KevConcentration, (1.0 - mean) * p.KevConcentration);
        }

        return epss is { } known ? new BetaParams(known * p.EpssConcentration, (1.0 - known) * p.EpssConcentration) : p.NoEpss;
    }

    private static double SeverityFactor(RiskInput input, ImpactParams p, Prng random)
    {
        if (input.CvssBaseScore is { } cvss)
        {
            return Math.Clamp(cvss / 10.0, 0.0, 1.0);
        }

        return input.DatabaseSeverity?.ToUpperInvariant() switch
        {
            "CRITICAL" => p.CriticalSeverityFactor,
            "HIGH" => p.HighSeverityFactor,
            "MODERATE" or "MEDIUM" => p.ModerateSeverityFactor,
            "LOW" => p.LowSeverityFactor,
            _ => p.UnknownSeverityLow + ((p.UnknownSeverityHigh - p.UnknownSeverityLow) * random.NextOpenUnit()),
        };
    }

    /// <summary>The empirical quantile by the nearest-rank rule on sorted samples.</summary>
    public static double Quantile(double[] sorted, double q)
    {
        // The small subtraction keeps 0.95 * 100 from rounding up to 96 (binary floating point has no exact 0.95).
        int index = (int)Math.Ceiling((q * sorted.Length) - 1e-9) - 1;
        return sorted[Math.Clamp(index, 0, sorted.Length - 1)];
    }

    /// <summary>The mean of the worst (1 - alpha) share of the samples: conditional value at risk.</summary>
    public static double TailMean(double[] sorted, double alpha)
    {
        int tail = Math.Max(1, (int)Math.Ceiling((sorted.Length * (1.0 - alpha)) - 1e-9));
        double sum = 0;

        for (int i = sorted.Length - tail; i < sorted.Length; i++)
        {
            sum += sorted[i];
        }

        return sum / tail;
    }
}

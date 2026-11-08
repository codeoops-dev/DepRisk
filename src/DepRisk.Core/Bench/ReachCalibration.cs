using DepRisk.Core.Risk;

namespace DepRisk.Core.Bench;

/// <summary>Where the Beta prior of a label comes from before the observed counts are added.</summary>
public enum ReachPrior
{
    /// <summary>Beta(1, 1): no opinion. The fitted numbers then depend on the data only.</summary>
    Uniform,

    /// <summary>The parameters the fit starts from (the defaults or a parameters file): the observed counts update them.</summary>
    Current,
}

/// <summary>One reachability label of the fit: what was observed and what the parameter was and became.</summary>
public sealed record ReachLabelFit(
    string Label,
    int Count,
    int TrulyReachable,
    double? ObservedRate,
    BetaParams Prior,
    BetaParams Before,
    BetaParams After,
    bool Fitted);

public sealed record ReachFit(IReadOnlyList<ReachLabelFit> Labels, ReachParams Reach);

/// <summary>
/// Fits the Reach factor of the risk model from labeled data (docs/benchmarks.md). For each reachability label the factor is the
/// probability that the vulnerable code is really exercised, so its distribution is the posterior of that rate: with a Beta prior and
/// <c>k</c> truly reachable findings out of <c>n</c> with that label it is Beta(alpha + k, beta + n - k). A label with fewer than
/// <c>minCount</c> findings with a known truth keeps its parameter: a handful of cases must not replace a placeholder with noise. Pure.
/// </summary>
public static class ReachCalibration
{
    public const int DefaultMinCount = 20;
    public const int MaxMinCount = 1_000_000;

    public const string Reachable = "reachable";
    public const string PossiblyReachable = "possibly-reachable";
    public const string Unknown = "unknown";
    public const string Unreachable = "unreachable";
    public const string NotAnalyzed = "not-analyzed";

    public static readonly IReadOnlyList<string> Labels = [Reachable, PossiblyReachable, Unknown, Unreachable, NotAnalyzed];

    public static ReachFit Fit(IReadOnlyList<(string Label, bool Truth)> observations, ReachParams start, ReachPrior prior, int minCount)
    {
        ArgumentNullException.ThrowIfNull(observations);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentOutOfRangeException.ThrowIfLessThan(minCount, 1);

        foreach ((string label, _) in observations)
        {
            if (!Labels.Contains(label, StringComparer.Ordinal))
            {
                throw new ArgumentException($"unknown reachability label '{label}'.", nameof(observations));
            }
        }

        List<ReachLabelFit> fits = [];

        foreach (string label in Labels)
        {
            int n = observations.Count(o => o.Label == label);
            int k = observations.Count(o => o.Label == label && o.Truth);
            BetaParams before = Select(start, label);
            BetaParams basis = prior == ReachPrior.Uniform ? new BetaParams(1, 1) : before;
            bool fitted = n >= minCount;
            BetaParams after = fitted ? new BetaParams(basis.Alpha + k, basis.Beta + (n - k)) : before;

            fits.Add(new ReachLabelFit(label, n, k, n == 0 ? null : BenchMetrics.Round((double)k / n), basis, before, after, fitted));
        }

        BetaParams After(string label) => fits.Single(f => f.Label == label).After;

        return new ReachFit(
            fits,
            new ReachParams(After(Reachable), After(PossiblyReachable), After(Unknown), After(Unreachable), After(NotAnalyzed)));
    }

    private static BetaParams Select(ReachParams reach, string label) => label switch
    {
        Reachable => reach.Reachable,
        PossiblyReachable => reach.PossiblyReachable,
        Unknown => reach.Unknown,
        Unreachable => reach.Unreachable,
        NotAnalyzed => reach.NotAnalyzed,
        _ => throw new ArgumentOutOfRangeException(nameof(label), label, "unknown reachability label"),
    };
}

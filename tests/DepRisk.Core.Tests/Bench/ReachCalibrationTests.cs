using DepRisk.Core.Bench;
using DepRisk.Core.Risk;
using Xunit;

namespace DepRisk.Core.Tests.Bench;

public sealed class ReachCalibrationTests
{
    private static readonly ReachParams Start = RiskParameters.Default.Reach;

    private static List<(string, bool)> Observe(string label, int total, int reachable) =>
        Enumerable.Range(0, total).Select(i => (label, i < reachable)).ToList();

    private static ReachLabelFit Of(ReachFit fit, string label) => fit.Labels.Single(l => l.Label == label);

    [Fact]
    public void With_a_uniform_prior_the_posterior_is_one_plus_the_hits_and_one_plus_the_misses()
    {
        // 20 of 25 reachable: Beta(1 + 20, 1 + 5).
        ReachFit fit = ReachCalibration.Fit(Observe("reachable", 25, 20), Start, ReachPrior.Uniform, 20);

        ReachLabelFit f = Of(fit, "reachable");
        Assert.True(f.Fitted);
        Assert.Equal(25, f.Count);
        Assert.Equal(20, f.TrulyReachable);
        Assert.Equal(0.8, f.ObservedRate);
        Assert.Equal(new BetaParams(1, 1), f.Prior);
        Assert.Equal(new BetaParams(21, 6), f.After);
        Assert.Equal(new BetaParams(21, 6), fit.Reach.Reachable);
    }

    [Fact]
    public void With_the_current_parameters_as_prior_the_counts_update_them()
    {
        // Default reachable is Beta(9, 1): 9 + 20 and 1 + 5.
        ReachFit fit = ReachCalibration.Fit(Observe("reachable", 25, 20), Start, ReachPrior.Current, 20);

        Assert.Equal(new BetaParams(9, 1), Of(fit, "reachable").Prior);
        Assert.Equal(new BetaParams(29, 6), fit.Reach.Reachable);
    }

    [Fact]
    public void A_label_with_too_few_observations_keeps_its_parameter_and_says_so()
    {
        ReachFit fit = ReachCalibration.Fit(Observe("unreachable", 19, 0), Start, ReachPrior.Uniform, 20);

        ReachLabelFit f = Of(fit, "unreachable");
        Assert.False(f.Fitted);
        Assert.Equal(19, f.Count);
        Assert.Equal(Start.Unreachable, f.After);
        Assert.Equal(Start.Unreachable, fit.Reach.Unreachable);

        // The twentieth observation tips it over.
        Assert.True(Of(ReachCalibration.Fit(Observe("unreachable", 20, 1), Start, ReachPrior.Uniform, 20), "unreachable").Fitted);
    }

    [Fact]
    public void Every_label_is_fitted_on_its_own_observations()
    {
        List<(string, bool)> data = [.. Observe("reachable", 10, 9), .. Observe("unknown", 10, 3), .. Observe("not-analyzed", 4, 4)];
        ReachFit fit = ReachCalibration.Fit(data, Start, ReachPrior.Uniform, 10);

        Assert.Equal(new BetaParams(10, 2), fit.Reach.Reachable);
        Assert.Equal(new BetaParams(4, 8), fit.Reach.Unknown);
        Assert.Equal(Start.NotAnalyzed, fit.Reach.NotAnalyzed);
        Assert.Equal(Start.PossiblyReachable, fit.Reach.PossiblyReachable);
        Assert.Equal(5, fit.Labels.Count);
        Assert.Null(Of(fit, "possibly-reachable").ObservedRate);
    }

    [Fact]
    public void A_label_whose_findings_are_never_reachable_gets_a_proper_beta()
    {
        ReachFit fit = ReachCalibration.Fit(Observe("unreachable", 30, 0), Start, ReachPrior.Uniform, 20);

        Assert.Equal(new BetaParams(1, 31), fit.Reach.Unreachable);
        Assert.Null((RiskParameters.Default with { Reach = fit.Reach }).Validate());
    }

    [Fact]
    public void Without_observations_nothing_changes()
    {
        ReachFit fit = ReachCalibration.Fit([], Start, ReachPrior.Uniform, 1);

        Assert.Equal(Start, fit.Reach);
        Assert.All(fit.Labels, l => Assert.False(l.Fitted));
    }

    [Fact]
    public void An_unknown_label_and_a_minimum_below_one_are_refused()
    {
        Assert.Throws<ArgumentException>(() => ReachCalibration.Fit([("maybe", true)], Start, ReachPrior.Uniform, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => ReachCalibration.Fit([], Start, ReachPrior.Uniform, 0));
    }
}

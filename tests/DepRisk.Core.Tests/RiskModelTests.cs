using DepRisk.Core.Reach;
using DepRisk.Core.Risk;
using Xunit;

namespace DepRisk.Core.Tests;

public class RiskModelTests
{
    private static readonly RiskParameters Defaults = RiskParameters.Default;

    private static RiskInput Input(
        string key = "F-1|P|1.0.0",
        string? reach = null,
        double? epss = null,
        bool kev = false,
        bool ransomware = false,
        double? cvss = null,
        string? severity = null) => new(key, reach, epss, kev, ransomware, cvss, severity);

    private static RiskDistribution One(RiskInput input, ulong seed = 1, int samples = 4000, RiskParameters? p = null) =>
        RiskModel.Evaluate([input], p ?? Defaults, seed, samples)[0];

    // --- the generator ---

    [Fact]
    public void The_same_seed_gives_the_same_numbers_and_other_seeds_do_not()
    {
        Prng a = new(42);
        Prng b = new(42);
        Prng c = new(43);

        ulong[] first = Enumerable.Range(0, 20).Select(_ => a.NextUInt64()).ToArray();

        Assert.Equal(first, Enumerable.Range(0, 20).Select(_ => b.NextUInt64()).ToArray());
        Assert.NotEqual(first, Enumerable.Range(0, 20).Select(_ => c.NextUInt64()).ToArray());
    }

    [Fact]
    public void The_generator_is_pinned_so_that_results_cannot_drift_between_versions_or_platforms()
    {
        // Reference values of xoshiro256** seeded through SplitMix64 (seed 0). If these change, every stored result changes.
        Prng random = new(0);

        Assert.Equal(new ulong[] { 11091344671253066420UL, 13793997310169335082UL, 1900383378846508768UL }, new[] { random.NextUInt64(), random.NextUInt64(), random.NextUInt64() });
    }

    [Fact]
    public void Uniform_numbers_are_in_the_open_unit_interval_with_the_right_mean()
    {
        Prng random = new(7);
        double[] values = Enumerable.Range(0, 100_000).Select(_ => random.NextOpenUnit()).ToArray();

        Assert.All(values, v => Assert.True(v > 0.0 && v < 1.0));
        Assert.True(Math.Abs(values.Average() - 0.5) < 0.005);
    }

    [Theory]
    [InlineData(2.0, 2.0)]
    [InlineData(9.0, 1.0)]
    [InlineData(1.0, 49.0)]
    [InlineData(0.5, 9.5)]
    [InlineData(0.5, 0.5)]
    [InlineData(20.0, 5.0)]
    public void Beta_samples_have_the_mean_and_variance_of_the_distribution(double alpha, double beta)
    {
        Prng random = new((ulong)(alpha * 1000 + beta));
        double[] values = Enumerable.Range(0, 200_000).Select(_ => random.NextBeta(alpha, beta)).ToArray();

        double mean = values.Average();
        double variance = values.Select(v => (v - mean) * (v - mean)).Sum() / values.Length;
        double expectedMean = alpha / (alpha + beta);
        double expectedVariance = alpha * beta / ((alpha + beta) * (alpha + beta) * (alpha + beta + 1));

        Assert.All(values, v => Assert.True(v >= 0.0 && v <= 1.0));
        Assert.True(Math.Abs(mean - expectedMean) < 0.004, $"mean {mean} vs {expectedMean}");
        Assert.True(Math.Abs(variance - expectedVariance) < 0.12 * expectedVariance + 1e-5, $"variance {variance} vs {expectedVariance}");
    }

    [Fact]
    public void Stream_seeds_depend_on_the_key_and_the_seed()
    {
        Assert.Equal(Prng.StreamSeed(1, "A"), Prng.StreamSeed(1, "A"));
        Assert.NotEqual(Prng.StreamSeed(1, "A"), Prng.StreamSeed(1, "B"));
        Assert.NotEqual(Prng.StreamSeed(1, "A"), Prng.StreamSeed(2, "A"));
    }

    // --- the model ---

    [Fact]
    public void The_same_inputs_and_seed_give_identical_distributions_and_another_seed_gives_different_ones()
    {
        RiskInput input = Input(reach: ReachLabels.Reachable, epss: 0.3, cvss: 7.5);

        Assert.Equal(One(input, seed: 5), One(input, seed: 5));
        Assert.NotEqual(One(input, seed: 5).Mean, One(input, seed: 6).Mean);
    }

    [Fact]
    public void A_finding_s_numbers_do_not_depend_on_the_other_findings_or_their_order()
    {
        RiskInput a = Input("A|P|1", ReachLabels.Reachable, 0.2, cvss: 8.0);
        RiskInput b = Input("B|P|1", ReachLabels.Unreachable, 0.6, kev: true);
        RiskInput c = Input("C|P|1", null, null, severity: "HIGH");

        RiskDistribution alone = One(a, seed: 9);
        IReadOnlyList<RiskDistribution> together = RiskModel.Evaluate([c, b, a], Defaults, 9, 4000);
        IReadOnlyList<RiskDistribution> reordered = RiskModel.Evaluate([a, c, b], Defaults, 9, 4000);

        Assert.Equal(alone, together[2]);
        Assert.Equal(alone, reordered[0]);
    }

    [Fact]
    public void The_key_is_case_insensitive_so_that_ids_written_differently_are_the_same_finding()
    {
        Assert.Equal(One(Input("ghsa-1|p|1")), One(Input("GHSA-1|P|1")));
    }

    [Fact]
    public void Quantiles_and_the_tail_mean_are_ordered()
    {
        RiskDistribution d = One(Input(reach: ReachLabels.PossiblyReachable, epss: 0.4, cvss: 9.0), samples: 20_000);

        Assert.True(d.P50 <= d.P90 && d.P90 <= d.P95);
        Assert.True(d.P95 <= d.Cvar95);
        Assert.True(d.Mean > 0 && d.Mean <= 10);
        Assert.True(d.Cvar95 > d.Mean);
    }

    [Fact]
    public void The_means_of_the_factors_follow_the_parameters()
    {
        RiskDistribution d = One(Input(reach: ReachLabels.Reachable, epss: 0.25, cvss: 8.0), samples: 50_000);

        Assert.True(Math.Abs(d.ReachMean - 0.9) < 0.01);                 // Beta(9, 1)
        Assert.True(Math.Abs(d.ExploitMean - 0.25) < 0.01);              // Beta(5, 15)
        Assert.True(Math.Abs(d.ImpactMean - (4.5 * 0.8)) < 0.05);        // Uniform(3, 6) x CVSS / 10
        Assert.True(Math.Abs(d.Mean - (d.ReachMean * d.ExploitMean * d.ImpactMean)) < 0.05);   // the factors are independent
    }

    [Fact]
    public void Reachability_orders_the_risk_of_otherwise_equal_findings()
    {
        double Mean(string? label) => One(Input(reach: label, epss: 0.3, cvss: 7.0), samples: 8000).Mean;

        double reachable = Mean(ReachLabels.Reachable);
        double possibly = Mean(ReachLabels.PossiblyReachable);
        double unknown = Mean(ReachLabels.Unknown);
        double unreachable = Mean(ReachLabels.Unreachable);

        Assert.True(reachable > possibly && possibly > unknown && unknown > unreachable, $"{reachable} {possibly} {unknown} {unreachable}");
        Assert.True(unreachable > 0, "unreachable is small, not zero: the analyzer is not perfect");
    }

    [Fact]
    public void Not_analyzed_is_treated_like_unknown_never_like_unreachable()
    {
        double notAnalyzed = One(Input(reach: null, epss: 0.3, cvss: 7.0), samples: 8000).Mean;
        double unreachable = One(Input(reach: ReachLabels.Unreachable, epss: 0.3, cvss: 7.0), samples: 8000).Mean;

        Assert.True(notAnalyzed > 5 * unreachable);
    }

    [Fact]
    public void Being_in_KEV_raises_the_exploit_probability_and_ransomware_use_raises_it_more()
    {
        double Exploit(bool kev, bool ransomware, double? epss) => One(Input(epss: epss, kev: kev, ransomware: ransomware), samples: 20_000).ExploitMean;

        Assert.True(Exploit(false, false, 0.05) < 0.1);
        Assert.True(Exploit(true, false, 0.05) > 0.6);
        Assert.True(Exploit(true, true, 0.05) > Exploit(true, false, 0.05));
        Assert.True(Exploit(true, false, 0.95) > 0.9);   // KEV never lowers a high EPSS
    }

    [Fact]
    public void Without_epss_the_prior_applies_and_is_wide()
    {
        RiskDistribution d = One(Input(epss: null), samples: 20_000);

        Assert.True(Math.Abs(d.ExploitMean - 0.05) < 0.01);
        Assert.Equal(new BetaParams(0.5, 9.5), RiskModel.ExploitFor(Input(epss: null), Defaults.Exploit));
    }

    [Fact]
    public void Epss_is_clamped_away_from_zero_and_one_so_that_the_beta_stays_valid()
    {
        Assert.True(RiskModel.ExploitFor(Input(epss: 0.0), Defaults.Exploit).Alpha > 0);
        Assert.True(RiskModel.ExploitFor(Input(epss: 1.0), Defaults.Exploit).Beta > 0);
    }

    [Fact]
    public void Severity_comes_from_cvss_then_the_database_rating_then_an_uncertain_factor()
    {
        double Impact(double? cvss, string? severity) => One(Input(cvss: cvss, severity: severity), samples: 20_000).ImpactMean;

        Assert.True(Math.Abs(Impact(10.0, null) - 4.5) < 0.05);
        Assert.True(Math.Abs(Impact(null, "CRITICAL") - (4.5 * 0.95)) < 0.05);
        Assert.True(Math.Abs(Impact(null, "low") - (4.5 * 0.2)) < 0.05);
        Assert.True(Math.Abs(Impact(null, "MEDIUM") - Impact(null, "moderate")) < 1e-9);
        Assert.True(Math.Abs(Impact(null, null) - (4.5 * 0.55)) < 0.06);
        Assert.True(Math.Abs(Impact(9.0, "LOW") - (4.5 * 0.9)) < 0.05);   // CVSS wins over the rating
    }

    [Fact]
    public void Unknown_severity_makes_the_tail_wider_than_a_known_one_with_the_same_mean()
    {
        RiskParameters equalMeans = Defaults with { Impact = Defaults.Impact with { LowSeverityFactor = 0.55 } };

        RiskDistribution known = One(Input(reach: ReachLabels.Reachable, epss: 0.5, severity: "LOW"), samples: 30_000, p: equalMeans);
        RiskDistribution unknown = One(Input(reach: ReachLabels.Reachable, epss: 0.5, severity: null), samples: 30_000, p: equalMeans);

        Assert.True(Math.Abs(known.Mean - unknown.Mean) < 0.1);
        Assert.True(unknown.P95 > known.P95);
    }

    [Theory]
    [InlineData(99)]
    [InlineData(200_001)]
    public void The_number_of_samples_is_bounded(int samples)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => RiskModel.Evaluate([Input()], Defaults, 1, samples));
    }

    [Fact]
    public void The_total_work_is_bounded()
    {
        RiskInput[] many = Enumerable.Range(0, 600).Select(i => Input($"F-{i}|P|1")).ToArray();

        Assert.Throws<ArgumentOutOfRangeException>(() => RiskModel.Evaluate(many, Defaults, 1, 200_000));
    }

    [Fact]
    public void Quantile_and_tail_mean_follow_their_definitions()
    {
        double[] sorted = Enumerable.Range(1, 100).Select(i => (double)i).ToArray();

        Assert.Equal(50, RiskModel.Quantile(sorted, 0.50));
        Assert.Equal(95, RiskModel.Quantile(sorted, 0.95));
        Assert.Equal(100, RiskModel.Quantile(sorted, 1.0));
        Assert.Equal(1, RiskModel.Quantile(sorted, 0.0));
        Assert.Equal(98, RiskModel.TailMean(sorted, 0.95), 6);   // mean of 96..100
    }

    // --- the parameters ---

    [Fact]
    public void The_defaults_are_valid_and_their_canonical_text_is_stable()
    {
        Assert.Null(Defaults.Validate());
        Assert.Equal(Defaults.Canonical(), RiskParameters.Default.Canonical());
        Assert.NotEqual(Defaults.Canonical(), (Defaults with { Exploit = Defaults.Exploit with { KevMean = 0.71 } }).Canonical());
    }

    [Fact]
    public void Invalid_parameters_are_rejected_with_the_name_of_the_problem()
    {
        Assert.Contains("reach.reachable", (Defaults with { Reach = Defaults.Reach with { Reachable = new BetaParams(0, 1) } }).Validate());
        Assert.Contains("reach.unknown", (Defaults with { Reach = Defaults.Reach with { Unknown = new BetaParams(double.NaN, 1) } }).Validate());
        Assert.Contains("concentrations", (Defaults with { Exploit = Defaults.Exploit with { EpssConcentration = 0 } }).Validate());
        Assert.Contains("KEV means", (Defaults with { Exploit = Defaults.Exploit with { KevMean = 1.0 } }).Validate());
        Assert.Contains("low <= high", (Defaults with { Impact = Defaults.Impact with { Low = 7, High = 6 } }).Validate());
        Assert.Contains("severity factors", (Defaults with { Impact = Defaults.Impact with { CriticalSeverityFactor = 1.5 } }).Validate());
        Assert.Throws<ArgumentException>(() => RiskModel.Evaluate([Input()], Defaults with { Impact = Defaults.Impact with { Low = -1 } }, 1, 1000));
    }
}

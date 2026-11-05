using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Core.Policy;
using Xunit;

namespace DepRisk.Core.Tests;

public class PolicyExpressionTests
{
    private static RankedFinding Finding(
        string id = "F-1",
        string? severity = null,
        double? cvss = null,
        double? epss = null,
        bool kev = false,
        bool ransomware = false,
        bool direct = true,
        string[]? fixedVersions = null) =>
        new(
            1,
            id,
            [],
            null,
            severity,
            new FindingPackage("Pkg", "1.0.0"),
            fixedVersions ?? [],
            [new FindingLocation("App", "net10.0", direct)],
            new FindingSignals(
                cvss is null ? null : new CvssSignal("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss.Value, "HIGH"),
                epss is null ? null : new EpssSignal("CVE-2025-0001", epss.Value, 0.5),
                kev ? new KevSignal("CVE-2025-0001", "2025-01-01", ransomware) : null));

    private static PolicyExpression Parse(string text)
    {
        Assert.True(PolicyExpression.TryParse(text, out PolicyExpression? expression, out string error), error);
        return expression!;
    }

    [Fact]
    public void Any_matches_every_finding()
    {
        Assert.True(Parse("any").Matches(Finding()));
    }

    [Fact]
    public void Kev_and_ransomware_terms()
    {
        Assert.True(Parse("kev").Matches(Finding(kev: true)));
        Assert.False(Parse("kev").Matches(Finding()));
        Assert.True(Parse("ransomware").Matches(Finding(kev: true, ransomware: true)));
        Assert.False(Parse("ransomware").Matches(Finding(kev: true)));
    }

    [Fact]
    public void Direct_and_fixable_terms()
    {
        Assert.True(Parse("direct").Matches(Finding(direct: true)));
        Assert.False(Parse("direct").Matches(Finding(direct: false)));
        Assert.True(Parse("fixable").Matches(Finding(fixedVersions: ["2.0.0"])));
        Assert.False(Parse("fixable").Matches(Finding()));
    }

    [Theory]
    [InlineData("cvss>=9", 9.0, true)]
    [InlineData("cvss>=9", 8.9, false)]
    [InlineData("cvss>9", 9.0, false)]
    [InlineData("cvss>9", 9.1, true)]
    [InlineData("cvss>=0", 0.0, true)]
    [InlineData("CVSS >= 7.5", 7.5, true)]
    public void Cvss_comparisons(string policy, double score, bool expected)
    {
        Assert.Equal(expected, Parse(policy).Matches(Finding(cvss: score)));
    }

    [Theory]
    [InlineData("epss>=0.1", 0.1, true)]
    [InlineData("epss>=0.1", 0.0999, false)]
    [InlineData("epss>0.5", 0.5, false)]
    [InlineData("epss>0.5", 0.51, true)]
    public void Epss_comparisons(string policy, double probability, bool expected)
    {
        Assert.Equal(expected, Parse(policy).Matches(Finding(epss: probability)));
    }

    [Fact]
    public void A_missing_signal_never_matches_a_comparison_even_a_trivial_one()
    {
        Assert.False(Parse("cvss>=0").Matches(Finding()));
        Assert.False(Parse("epss>=0").Matches(Finding()));
    }

    [Theory]
    [InlineData("severity>=high", "CRITICAL", true)]
    [InlineData("severity>=high", "HIGH", true)]
    [InlineData("severity>=high", "MODERATE", false)]
    [InlineData("severity>=medium", "MODERATE", true)]
    [InlineData("severity>=moderate", "MEDIUM", true)]
    [InlineData("severity>=low", "LOW", true)]
    [InlineData("severity>=low", null, false)]
    [InlineData("severity>=critical", "HIGH", false)]
    public void Severity_levels_are_ordered(string policy, string? severity, bool expected)
    {
        Assert.Equal(expected, Parse(policy).Matches(Finding(severity: severity)));
    }

    [Fact]
    public void And_requires_every_term_for_the_same_finding()
    {
        PolicyExpression policy = Parse("kev&fixable");

        Assert.True(policy.Matches(Finding(kev: true, fixedVersions: ["2.0.0"])));
        Assert.False(policy.Matches(Finding(kev: true)));
        Assert.False(policy.Matches(Finding(fixedVersions: ["2.0.0"])));
    }

    [Fact]
    public void Comma_means_any_clause_may_trip_the_gate()
    {
        PolicyExpression policy = Parse("kev&fixable, cvss>=9");

        Assert.True(policy.Matches(Finding(cvss: 9.8)));
        Assert.True(policy.Matches(Finding(kev: true, fixedVersions: ["2"])));
        Assert.False(policy.Matches(Finding(kev: true, cvss: 5.0)));
    }

    [Fact]
    public void Evaluate_returns_the_matching_findings_in_order()
    {
        RankedFinding[] findings = [Finding("A", cvss: 9.8), Finding("B", cvss: 2.0), Finding("C", cvss: 9.0)];

        IReadOnlyList<RankedFinding> tripped = Parse("cvss>=9").Evaluate(findings);

        Assert.Equal(new[] { "A", "C" }, tripped.Select(f => f.Id).ToArray());
    }

    [Fact]
    public void Terms_are_case_insensitive_and_whitespace_tolerant()
    {
        Assert.True(Parse("  KEV  &  Fixable ").Matches(Finding(kev: true, fixedVersions: ["2"])));
    }

    [Fact]
    public void The_original_text_is_kept()
    {
        Assert.Equal("kev & fixable", Parse("  kev & fixable ").Text);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("kev,")]
    [InlineData(",kev")]
    [InlineData("kev&")]
    [InlineData("&kev")]
    [InlineData("kev&&fixable")]
    [InlineData("nonsense")]
    [InlineData("cvss")]
    [InlineData("cvss>=")]
    [InlineData("cvss>=abc")]
    [InlineData("cvss>=11")]
    [InlineData("cvss>=-1")]
    [InlineData("cvss>=NaN")]
    [InlineData("epss>=1.5")]
    [InlineData("epss>=-0.1")]
    [InlineData("severity>high")]
    [InlineData("severity>=urgent")]
    [InlineData("severity>=none")]
    [InlineData("score>=5")]
    [InlineData("reachable>=1")]
    [InlineData("kev&reachables")]
    [InlineData("not-reachable")]
    [InlineData("!unreachable")]
    public void Invalid_policies_are_rejected_with_a_reason(string policy)
    {
        Assert.False(PolicyExpression.TryParse(policy, out PolicyExpression? expression, out string error));
        Assert.Null(expression);
        Assert.NotEqual(string.Empty, error);
    }

    [Fact]
    public void Null_is_rejected()
    {
        Assert.False(PolicyExpression.TryParse(null, out _, out _));
    }

    [Fact]
    public void Numbers_use_the_invariant_culture()
    {
        System.Globalization.CultureInfo original = System.Globalization.CultureInfo.CurrentCulture;

        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("fa-IR");

            Assert.True(Parse("cvss>=7.5").Matches(Finding(cvss: 7.5)));
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = original;
        }
    }

    private static RankedFinding WithReach(string? label) =>
        Finding() with { Reachability = label is null ? null : new FindingReach(label, "test", null) };

    [Theory]
    [InlineData("reachable", "reachable", true)]
    [InlineData("reachable", "possibly-reachable", false)]
    [InlineData("reachable", "unknown", false)]
    [InlineData("reachable", "unreachable", false)]
    [InlineData("possibly-reachable", "possibly-reachable", true)]
    [InlineData("possibly-reachable", "reachable", false)]
    [InlineData("reach-unknown", "unknown", true)]
    [InlineData("reach-unknown", "unreachable", false)]
    [InlineData("unreachable", "unreachable", true)]
    [InlineData("unreachable", "unknown", false)]
    [InlineData("not-unreachable", "reachable", true)]
    [InlineData("not-unreachable", "possibly-reachable", true)]
    [InlineData("not-unreachable", "unknown", true)]
    [InlineData("not-unreachable", "unreachable", false)]
    [InlineData("REACHABLE", "reachable", true)]
    public void Reachability_terms_match_the_label(string term, string label, bool expected)
    {
        Assert.Equal(expected, Parse(term).Matches(WithReach(label)));
    }

    [Theory]
    [InlineData("reachable")]
    [InlineData("possibly-reachable")]
    [InlineData("reach-unknown")]
    [InlineData("unreachable")]
    [InlineData("not-unreachable")]
    public void A_finding_that_was_not_analyzed_matches_no_reachability_term(string term)
    {
        // Not analyzed is not "unreachable" and not "reachable": the term is simply false, like any missing signal.
        Assert.False(Parse(term).Matches(WithReach(null)));
    }

    [Fact]
    public void Reachability_terms_combine_with_the_others_and_are_reported_as_used()
    {
        PolicyExpression gate = Parse("kev&not-unreachable,cvss>=9&reachable");

        Assert.True(gate.UsesReachability);
        Assert.False(Parse("kev&fixable,cvss>=9").UsesReachability);
        Assert.True(Parse("kev,reachable").UsesReachability);
        Assert.True(Parse("cvss>=9&direct&unreachable").UsesReachability);

        Assert.True(Parse("cvss>=9&reachable").Matches(Finding(cvss: 9.8) with { Reachability = new FindingReach("reachable", "static-path", "A.B.C") }));
        Assert.False(Parse("cvss>=9&reachable").Matches(Finding(cvss: 5.0) with { Reachability = new FindingReach("reachable", "static-path", "A.B.C") }));
    }

    [Fact]
    public void The_error_for_an_unknown_term_lists_the_reachability_terms()
    {
        PolicyExpression.TryParse("bogus", out _, out string error);

        Assert.Contains("not-unreachable", error);
    }
}

using DepRisk.Core.Advisories;
using DepRisk.Core.Versioning;
using Xunit;

namespace DepRisk.Core.Tests;

public class AdvisoryIndexTests
{
    private static RangeEvent Introduced(string v) => new("introduced", v);

    private static RangeEvent Fixed(string v) => new("fixed", v);

    private static RangeEvent LastAffected(string v) => new("last_affected", v);

    private static AffectedPackage Package(
        string name,
        IEnumerable<RangeEvent>? events = null,
        IEnumerable<string>? versions = null,
        string ecosystem = "NuGet",
        string rangeType = "ECOSYSTEM") =>
        new(
            ecosystem,
            name,
            events is null ? [] : [new AffectedRange(rangeType, events.ToList())],
            (versions ?? []).ToList());

    private static Advisory Advisory(string id, params AffectedPackage[] affected) =>
        new(id, [], null, false, [], null, affected);

    private static IReadOnlyList<AdvisoryMatch> Find(Advisory advisory, string package, string version) =>
        AdvisoryIndex.Build([advisory]).Find(package, NuGetVersion.Parse(version));

    private static bool Affected(Advisory advisory, string version) => Find(advisory, "Pkg", version).Count > 0;

    [Theory]
    [InlineData("0.0.1", true)]
    [InlineData("1.9.9", true)]
    [InlineData("2.0.0-beta", true)]
    [InlineData("2.0.0", false)]
    [InlineData("2.0.1", false)]
    public void Introduced_at_the_beginning_and_fixed_at_a_version(string version, bool expected)
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("0"), Fixed("2.0.0")]));

        Assert.Equal(expected, Affected(advisory, version));
    }

    [Theory]
    [InlineData("0.9.9", false)]
    [InlineData("1.0.0", true)]
    [InlineData("1.4.9", true)]
    [InlineData("1.5.0", false)]
    [InlineData("3.0.0", false)]
    public void A_bounded_interval_includes_introduced_and_excludes_fixed(string version, bool expected)
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("1.0.0"), Fixed("1.5.0")]));

        Assert.Equal(expected, Affected(advisory, version));
    }

    [Theory]
    [InlineData("1.2.0", true)]
    [InlineData("1.9.9", false)]
    [InlineData("2.0.0", false)]
    [InlineData("2.1.0", true)]
    [InlineData("2.5.0", false)]
    public void Several_intervals_in_one_range(string version, bool expected)
    {
        Advisory advisory = Advisory(
            "A-1",
            Package("Pkg", [Introduced("1.0.0"), Fixed("1.5.0"), Introduced("2.1.0"), Fixed("2.4.0")]));

        // 1.2.0 in first interval; 1.9.9 and 2.0.0 in the gap; 2.1.0 in the second; 2.5.0 after it.
        Assert.Equal(expected, Affected(advisory, version));
    }

    [Fact]
    public void Events_are_evaluated_in_version_order_whatever_the_input_order()
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Fixed("1.5.0"), Introduced("1.0.0")]));

        Assert.True(Affected(advisory, "1.2.0"));
        Assert.False(Affected(advisory, "1.5.0"));
    }

    [Theory]
    [InlineData("1.5.0", true)]
    [InlineData("1.5.1", false)]
    public void Last_affected_is_inclusive(string version, bool expected)
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("1.0.0"), LastAffected("1.5.0")]));

        Assert.Equal(expected, Affected(advisory, version));
    }

    [Fact]
    public void Without_a_fix_every_later_version_is_affected_and_no_fix_is_reported()
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("2.0.0")]));

        IReadOnlyList<AdvisoryMatch> matches = Find(advisory, "Pkg", "9.9.9");

        AdvisoryMatch match = Assert.Single(matches);
        Assert.Empty(match.FixedVersions);
        Assert.False(Affected(advisory, "1.9.9"));
    }

    [Fact]
    public void Fixed_versions_are_only_those_above_the_installed_version_in_ascending_order()
    {
        Advisory advisory = Advisory(
            "A-1",
            Package("Pkg", [Introduced("0"), Fixed("1.2.0"), Introduced("2.0.0"), Fixed("2.3.0")]));

        AdvisoryMatch match = Assert.Single(Find(advisory, "Pkg", "1.0.0"));
        Assert.Equal(new[] { "1.2.0", "2.3.0" }, match.FixedVersions.Select(v => v.ToString()).ToArray());

        AdvisoryMatch later = Assert.Single(Find(advisory, "Pkg", "2.1.0"));
        Assert.Equal(new[] { "2.3.0" }, later.FixedVersions.Select(v => v.ToString()).ToArray());
    }

    [Fact]
    public void Several_affected_entries_of_one_advisory_give_one_match_with_the_fixes_of_the_matching_entry()
    {
        Advisory advisory = Advisory(
            "A-1",
            Package("Pkg", [Introduced("4.9.0"), Fixed("4.9.7")]),
            Package("Pkg", [Introduced("6.8.0"), Fixed("6.8.2")]),
            Package("Pkg", [Introduced("6.11.0"), Fixed("6.11.2")]));

        AdvisoryMatch match = Assert.Single(Find(advisory, "Pkg", "6.8.1"));

        Assert.Equal(new[] { "6.8.2" }, match.FixedVersions.Select(v => v.ToString()).ToArray());
        Assert.Empty(Find(advisory, "Pkg", "6.9.0"));
    }

    [Fact]
    public void Explicit_versions_match_even_without_ranges_and_use_nuget_equality()
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", versions: ["1.2.3", "2.0.0-beta.1"]));

        Assert.True(Affected(advisory, "1.2.3"));
        Assert.True(Affected(advisory, "1.2.3.0"));
        Assert.True(Affected(advisory, "2.0.0-BETA.1"));
        Assert.False(Affected(advisory, "1.2.4"));
    }

    [Fact]
    public void Ranges_and_explicit_versions_are_combined()
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("1.0.0"), Fixed("1.1.0")], ["5.0.0"]));

        Assert.True(Affected(advisory, "1.0.5"));
        Assert.True(Affected(advisory, "5.0.0"));
        Assert.False(Affected(advisory, "3.0.0"));
    }

    [Fact]
    public void Package_ids_are_matched_ignoring_case()
    {
        Advisory advisory = Advisory("A-1", Package("SixLabors.ImageSharp", [Introduced("0"), Fixed("2.0.0")]));
        AdvisoryIndex index = AdvisoryIndex.Build([advisory]);

        Assert.Single(index.Find("sixlabors.imagesharp", NuGetVersion.Parse("1.0.0")));
        Assert.Single(index.Find("SIXLABORS.IMAGESHARP", NuGetVersion.Parse("1.0.0")));
        Assert.Empty(index.Find("SixLabors.ImageSharp.Web", NuGetVersion.Parse("1.0.0")));
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("Echo:NuGet")]
    [InlineData("PyPI")]
    public void Entries_of_other_ecosystems_are_ignored(string ecosystem)
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("0")], ecosystem: ecosystem));
        AdvisoryIndex index = AdvisoryIndex.Build([advisory]);

        Assert.Empty(index.Find("Pkg", NuGetVersion.Parse("1.0.0")));
        Assert.Equal(0, index.AdvisoryCount);
    }

    [Fact]
    public void Withdrawn_advisories_are_ignored()
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("0")])) with { Withdrawn = true };

        Assert.Empty(Find(advisory, "Pkg", "1.0.0"));
    }

    [Fact]
    public void Git_ranges_and_unknown_events_are_not_evaluated()
    {
        Advisory git = Advisory("A-1", Package("Pkg", [Introduced("0")], rangeType: "GIT"));
        Advisory limit = Advisory("A-2", Package("Pkg", [new RangeEvent("limit", "9.0.0")]));

        Assert.Empty(Find(git, "Pkg", "1.0.0"));
        Assert.Empty(Find(limit, "Pkg", "1.0.0"));
    }

    [Fact]
    public void Semver_ranges_are_evaluated_like_ecosystem_ranges()
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("0"), Fixed("2.0.0")], rangeType: "SEMVER"));

        Assert.True(Affected(advisory, "1.0.0"));
        Assert.False(Affected(advisory, "2.0.0"));
    }

    [Fact]
    public void Build_metadata_in_a_fixed_version_does_not_change_the_ordering()
    {
        Advisory advisory = Advisory("A-1", Package("Pkg", [Introduced("0"), Fixed("8.0.0+echo.1")]));

        Assert.True(Affected(advisory, "7.9.9"));
        Assert.False(Affected(advisory, "8.0.0"));
    }

    [Fact]
    public void Matches_are_ordered_by_advisory_id()
    {
        Advisory b = Advisory("B-2", Package("Pkg", [Introduced("0")]));
        Advisory a = Advisory("A-1", Package("Pkg", [Introduced("0")]));

        IReadOnlyList<AdvisoryMatch> matches = AdvisoryIndex.Build([b, a]).Find("Pkg", NuGetVersion.Parse("1.0.0"));

        Assert.Equal(new[] { "A-1", "B-2" }, matches.Select(m => m.Advisory.Id).ToArray());
    }

    [Fact]
    public void The_advisory_count_counts_advisories_with_a_nuget_entry()
    {
        AdvisoryIndex index = AdvisoryIndex.Build(
        [
            Advisory("A-1", Package("One", [Introduced("0")])),
            Advisory("A-2", Package("Two", [Introduced("0")]), Package("Three", [Introduced("0")])),
            Advisory("A-3", Package("Four", [Introduced("0")], ecosystem: "npm")),
        ]);

        Assert.Equal(2, index.AdvisoryCount);
    }
}

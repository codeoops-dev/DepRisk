using DepRisk.Core;
using DepRisk.Core.Advisories;
using DepRisk.Core.Versioning;
using Xunit;

namespace DepRisk.Core.Tests;

public class AdvisoryIndexNpmTests
{
    private static Advisory Advisory(string id, string ecosystem, string package, params (string Kind, string Version)[] events) =>
        new(
            id,
            [],
            null,
            false,
            [],
            null,
            [new AffectedPackage(ecosystem, package, [new AffectedRange("SEMVER", events.Select(e => new RangeEvent(e.Kind, e.Version)).ToList())], [])]);

    private static NuGetVersion V(string text) => Ecosystem.Npm.TryParseVersion(text, out NuGetVersion? v) ? v! : throw new InvalidOperationException(text);

    [Fact]
    public void An_npm_index_uses_npm_entries_only()
    {
        AdvisoryIndex index = AdvisoryIndex.Build(
            [
                Advisory("A-NPM", "npm", "lodash", ("introduced", "0"), ("fixed", "4.17.21")),
                Advisory("A-NUGET", "NuGet", "lodash", ("introduced", "0"), ("fixed", "9.0.0")),
            ],
            Ecosystem.Npm);

        Assert.Equal(Ecosystem.Npm, index.Ecosystem);
        Assert.Equal(1, index.AdvisoryCount);

        AdvisoryMatch match = Assert.Single(index.Find("lodash", V("4.17.20")));
        Assert.Equal("A-NPM", match.Advisory.Id);
        Assert.Equal(new[] { "4.17.21" }, match.FixedVersions.Select(v => v.ToString()).ToArray());
        Assert.Empty(index.Find("lodash", V("4.17.21")));
    }

    [Fact]
    public void The_default_index_is_still_for_nuget()
    {
        AdvisoryIndex index = AdvisoryIndex.Build(
        [
            Advisory("A-NPM", "npm", "lodash", ("introduced", "0"), ("fixed", "4.17.21")),
            Advisory("A-NUGET", "NuGet", "Some.Package", ("introduced", "0"), ("fixed", "2.0.0")),
        ]);

        Assert.Equal(Ecosystem.NuGet, index.Ecosystem);
        Assert.Equal(1, index.AdvisoryCount);
        Assert.Empty(index.Find("lodash", NuGetVersion.Parse("1.0.0")));
        Assert.Single(index.Find("Some.Package", NuGetVersion.Parse("1.0.0")));
    }

    [Fact]
    public void Package_names_match_ignoring_case_including_scopes()
    {
        AdvisoryIndex index = AdvisoryIndex.Build(
            [Advisory("A-1", "npm", "@Babel/Code-Frame", ("introduced", "0"), ("fixed", "7.0.0"))],
            Ecosystem.Npm);

        Assert.Single(index.Find("@babel/code-frame", V("6.9.9")));
        Assert.Single(index.Find("@BABEL/CODE-FRAME", V("6.9.9")));
        Assert.Empty(index.Find("babel/code-frame", V("6.9.9")));
    }

    [Fact]
    public void Prerelease_versions_are_below_their_release_in_ranges()
    {
        AdvisoryIndex index = AdvisoryIndex.Build(
            [Advisory("A-1", "npm", "pkg", ("introduced", "1.0.0"), ("fixed", "2.0.0"))],
            Ecosystem.Npm);

        Assert.Empty(index.Find("pkg", V("1.0.0-rc.1")));
        Assert.Single(index.Find("pkg", V("1.0.0")));
        Assert.Single(index.Find("pkg", V("2.0.0-rc.1")));
        Assert.Empty(index.Find("pkg", V("2.0.0")));
    }

    [Fact]
    public void An_event_that_is_not_strict_semver_is_not_evaluated_for_npm()
    {
        // A four-part version is a valid NuGet version but not an npm version: the event is dropped, never guessed at.
        AdvisoryIndex index = AdvisoryIndex.Build(
            [Advisory("A-1", "npm", "pkg", ("introduced", "0"), ("fixed", "1.2.3.4"))],
            Ecosystem.Npm);

        Assert.Single(index.Find("pkg", V("9.9.9")));
    }

    [Fact]
    public void Explicitly_listed_versions_match_for_npm()
    {
        Advisory listed = new(
            "A-LIST",
            [],
            null,
            false,
            [],
            null,
            [new AffectedPackage("npm", "pkg", [], ["1.2.3", "not-a-version"])]);

        AdvisoryIndex index = AdvisoryIndex.Build([listed], Ecosystem.Npm);

        Assert.Single(index.Find("pkg", V("1.2.3")));
        Assert.Empty(index.Find("pkg", V("1.2.4")));
    }
}

using DepRisk.Core;
using DepRisk.Core.Advisories;
using DepRisk.Core.Versioning;
using Xunit;

namespace DepRisk.Core.Tests;

public class EcosystemTests
{
    [Fact]
    public void Known_ecosystems_are_found_by_their_identifier_only()
    {
        Assert.True(Ecosystem.TryFromId("nuget", out Ecosystem? nuget));
        Assert.Equal("NuGet", nuget!.OsvName);
        Assert.True(Ecosystem.TryFromId("npm", out Ecosystem? npm));
        Assert.Equal("npm", npm!.OsvName);

        Assert.False(Ecosystem.TryFromId("NuGet", out _));
        Assert.False(Ecosystem.TryFromId("auto", out _));
        Assert.False(Ecosystem.TryFromId("", out _));
        Assert.False(Ecosystem.TryFromId(null, out _));
        Assert.Throws<ArgumentException>(() => Ecosystem.FromId("pypi"));
    }

    [Theory]
    [InlineData("1.2.3")]
    [InlineData("0.0.0")]
    [InlineData("10.20.30")]
    [InlineData("1.0.0-alpha")]
    [InlineData("1.0.0-alpha.1")]
    [InlineData("1.0.0-0.3.7")]
    [InlineData("1.0.0-x-y-z.--")]
    [InlineData("1.0.0-beta+exp.sha.5114f85")]
    [InlineData("1.0.0+20130313144700")]
    [InlineData("1.0.0-rc.1+001")]
    public void Npm_accepts_valid_semver(string text)
    {
        Assert.True(Ecosystem.Npm.TryParseVersion(text, out NuGetVersion? version));
        Assert.NotNull(version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1")]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("01.2.3")]
    [InlineData("1.02.3")]
    [InlineData("1.2.03")]
    [InlineData("v1.2.3")]
    [InlineData("=1.2.3")]
    [InlineData("^1.2.3")]
    [InlineData("1.2.x")]
    [InlineData("1.2.3-")]
    [InlineData("1.2.3-01")]
    [InlineData("1.2.3-a..b")]
    [InlineData("1.2.3-a_b")]
    [InlineData("1.2.3+")]
    [InlineData("1.2.3+a..b")]
    [InlineData("-1.2.3")]
    [InlineData("1.2.3 ")]
    [InlineData(" 1.2.3")]
    public void Npm_rejects_everything_that_is_not_strict_semver(string text)
    {
        Assert.False(Ecosystem.Npm.TryParseVersion(text, out NuGetVersion? version));
        Assert.Null(version);
    }

    [Fact]
    public void Npm_rejects_null_and_numbers_beyond_int()
    {
        Assert.False(Ecosystem.Npm.TryParseVersion(null, out _));
        Assert.False(Ecosystem.Npm.TryParseVersion("99999999999.0.0", out _));
    }

    [Fact]
    public void Nuget_keeps_its_own_more_permissive_rules()
    {
        Assert.True(Ecosystem.NuGet.TryParseVersion("1.2.3.4", out NuGetVersion? four));
        Assert.Equal("1.2.3.4", four!.ToString());
        Assert.True(Ecosystem.NuGet.TryParseVersion("1.2", out NuGetVersion? two));
        Assert.Equal("1.2.0", two!.ToString());
    }

    [Fact]
    public void Npm_versions_order_like_semver()
    {
        // The example chain from semver.org, section 11.
        string[] ascending =
        [
            "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
            "2.0.0", "2.1.0", "2.1.1",
        ];

        List<NuGetVersion> parsed = ascending
            .Select(text => Ecosystem.Npm.TryParseVersion(text, out NuGetVersion? v) ? v! : throw new InvalidOperationException(text))
            .ToList();

        for (int i = 1; i < parsed.Count; i++)
        {
            Assert.True(parsed[i - 1] < parsed[i], $"{ascending[i - 1]} should be below {ascending[i]}");
        }
    }

    [Fact]
    public void Build_metadata_does_not_change_precedence_or_the_normalized_text()
    {
        Assert.True(Ecosystem.Npm.TryParseVersion("1.2.3+build.5", out NuGetVersion? withMetadata));
        Assert.True(Ecosystem.Npm.TryParseVersion("1.2.3", out NuGetVersion? plain));
        Assert.Equal(plain, withMetadata);
        Assert.Equal("1.2.3", withMetadata!.ToString());
    }

    [Fact]
    public void Known_difference_prerelease_identifiers_compare_ignoring_case()
    {
        // SemVer compares alphanumeric identifiers as plain ASCII ("Beta" < "alpha"); the shared implementation ignores case.
        // This test documents the difference (ADR 0010) so a change of behavior is noticed.
        Assert.True(Ecosystem.Npm.TryParseVersion("1.0.0-Beta", out NuGetVersion? upper));
        Assert.True(Ecosystem.Npm.TryParseVersion("1.0.0-beta", out NuGetVersion? lower));
        Assert.Equal(upper, lower);
    }
}

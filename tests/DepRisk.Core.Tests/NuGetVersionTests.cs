using DepRisk.Core.Versioning;
using Xunit;

namespace DepRisk.Core.Tests;

public class NuGetVersionTests
{
    [Theory]
    [InlineData("1")]
    [InlineData("1.2")]
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4")]
    [InlineData("0.0.0")]
    [InlineData("1.0.0-beta")]
    [InlineData("1.0.0-beta.1+build.5")]
    [InlineData("1.0.0+metadata")]
    [InlineData("8.0.0+echo.1")]
    [InlineData("  1.2.3  ")]
    [InlineData("1.0.0-rc-1")]
    public void Valid_versions_parse(string text)
    {
        Assert.True(NuGetVersion.TryParse(text, out NuGetVersion? version));
        Assert.NotNull(version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a")]
    [InlineData("v1.0.0")]
    [InlineData("1.2.3.4.5")]
    [InlineData("1..2")]
    [InlineData("-1")]
    [InlineData(".1")]
    [InlineData("1.")]
    [InlineData("1.0.0-")]
    [InlineData("1.0.0-be ta")]
    [InlineData("1.0.0-alpha..1")]
    [InlineData("1.0.0+")]
    [InlineData("1.0.0+meta data")]
    [InlineData("99999999999")]
    [InlineData("1.-2.3")]
    public void Invalid_versions_are_rejected(string text)
    {
        Assert.False(NuGetVersion.TryParse(text, out NuGetVersion? version));
        Assert.Null(version);
    }

    [Fact]
    public void Null_is_rejected_and_Parse_throws_on_bad_input()
    {
        Assert.False(NuGetVersion.TryParse(null, out _));
        Assert.Throws<FormatException>(() => NuGetVersion.Parse("nope"));
    }

    [Theory]
    [InlineData("1", "1.0.0")]
    [InlineData("1.0", "1.0.0")]
    [InlineData("1.0.0.0", "1.0.0")]
    [InlineData("1.0.0.1", "1.0.0.1")]
    [InlineData("1.02.3", "1.2.3")]
    [InlineData("1.0.0-Beta+meta", "1.0.0-Beta")]
    [InlineData("2.0.0-rc.1.2", "2.0.0-rc.1.2")]
    public void ToString_gives_the_normalized_form(string text, string expected)
    {
        Assert.Equal(expected, NuGetVersion.Parse(text).ToString());
    }

    [Theory]
    [InlineData("1.0", "1.0.0")]
    [InlineData("1.0.0", "1.0.0.0")]
    [InlineData("1.0.0+a", "1.0.0+b")]
    [InlineData("1.0.0-BETA", "1.0.0-beta")]
    [InlineData("1.01.0", "1.1.0")]
    [InlineData("1.0.0-beta.01", "1.0.0-beta.1")]
    [InlineData("8.0.0+echo.1", "8.0.0")]
    public void Equal_versions_compare_equal_and_hash_equal(string left, string right)
    {
        NuGetVersion a = NuGetVersion.Parse(left);
        NuGetVersion b = NuGetVersion.Parse(right);

        Assert.Equal(0, a.CompareTo(b));
        Assert.True(a.Equals(b));
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    // Strictly ascending. Every pair (i < j) must satisfy v[i] < v[j].
    private static readonly string[] Ascending =
    [
        "0.9",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.0.1",
        "1.0.1",
        "1.1",
        "2.0.0-alpha",
        "2.0",
        "10.0",
    ];

    [Fact]
    public void The_documented_ordering_holds_for_every_pair()
    {
        NuGetVersion[] versions = Ascending.Select(NuGetVersion.Parse).ToArray();

        for (int i = 0; i < versions.Length; i++)
        {
            for (int j = i + 1; j < versions.Length; j++)
            {
                Assert.True(versions[i] < versions[j], $"{Ascending[i]} should be below {Ascending[j]}");
                Assert.True(versions[j] > versions[i], $"{Ascending[j]} should be above {Ascending[i]}");
                Assert.True(versions[i] <= versions[j]);
                Assert.True(versions[j] >= versions[i]);
                Assert.True(versions[i] != versions[j]);
            }
        }
    }

    [Fact]
    public void Sorting_a_shuffled_list_restores_the_order()
    {
        Random random = new(12345);
        string[] shuffled = Ascending.OrderBy(_ => random.Next()).ToArray();

        string[] sorted = shuffled.Select(NuGetVersion.Parse).Order().Select(v => v.ToString()).ToArray();

        Assert.Equal(Ascending.Select(s => NuGetVersion.Parse(s).ToString()).ToArray(), sorted);
    }

    [Fact]
    public void A_release_is_greater_than_its_prereleases()
    {
        Assert.True(NuGetVersion.Parse("1.0.0") > NuGetVersion.Parse("1.0.0-rc.99"));
    }

    [Fact]
    public void Numeric_labels_are_below_alphanumeric_labels_and_compared_as_numbers()
    {
        Assert.True(NuGetVersion.Parse("1.0.0-1") < NuGetVersion.Parse("1.0.0-alpha"));
        Assert.True(NuGetVersion.Parse("1.0.0-beta.2") < NuGetVersion.Parse("1.0.0-beta.11"));
        Assert.True(NuGetVersion.Parse("1.0.0-99999999999999999999") > NuGetVersion.Parse("1.0.0-9"));
    }

    [Fact]
    public void Alphanumeric_labels_ignore_case()
    {
        Assert.True(NuGetVersion.Parse("1.0.0-Alpha") < NuGetVersion.Parse("1.0.0-beta"));
        Assert.Equal(NuGetVersion.Parse("1.0.0-ALPHA"), NuGetVersion.Parse("1.0.0-alpha"));
    }

    [Fact]
    public void A_longer_label_list_is_greater_when_the_shared_labels_are_equal()
    {
        Assert.True(NuGetVersion.Parse("1.0.0-alpha") < NuGetVersion.Parse("1.0.0-alpha.1"));
    }

    [Fact]
    public void Comparing_with_null_is_greater()
    {
        Assert.Equal(1, NuGetVersion.Parse("1.0").CompareTo(null));
        Assert.False(NuGetVersion.Parse("1.0").Equals(null));
    }

    [Fact]
    public void Exposes_the_parsed_parts()
    {
        NuGetVersion version = NuGetVersion.Parse("1.2.3.4-rc.1+meta");

        Assert.Equal(1, version.Major);
        Assert.Equal(2, version.Minor);
        Assert.Equal(3, version.Patch);
        Assert.Equal(4, version.Revision);
        Assert.Equal(new[] { "rc", "1" }, version.ReleaseLabels.ToArray());
        Assert.Equal("meta", version.Metadata);
        Assert.True(version.IsPrerelease);
    }
}

using DepRisk.Core.Versioning;
using Xunit;

namespace DepRisk.Core.Tests;

public class NuGetVersionRangeTests
{
    private static NuGetVersionRange Range(string text)
    {
        Assert.True(NuGetVersionRange.TryParse(text, out NuGetVersionRange? range), $"'{text}' should parse");
        return range!;
    }

    private static bool In(string range, string version) => Range(range).Contains(NuGetVersion.Parse(version));

    [Theory]
    [InlineData("1.0", "0.9.9", false)]
    [InlineData("1.0", "1.0.0", true)]
    [InlineData("1.0", "1.0.1", true)]
    [InlineData("1.0", "99.0", true)]
    [InlineData("1.0.0", "1.0.0-beta", false)]
    public void A_plain_version_is_a_minimum_inclusive(string range, string version, bool expected)
    {
        Assert.Equal(expected, In(range, version));
    }

    [Theory]
    [InlineData("[1.0,2.0)", "0.9", false)]
    [InlineData("[1.0,2.0)", "1.0", true)]
    [InlineData("[1.0,2.0)", "1.9.9", true)]
    [InlineData("[1.0,2.0)", "2.0", false)]
    [InlineData("[1.0,2.0)", "2.0.0-beta", true)]
    [InlineData("[1.0, 2.0]", "2.0", true)]
    [InlineData("[1.0, 2.0]", "2.0.1", false)]
    [InlineData("(1.0,2.0)", "1.0", false)]
    [InlineData("(1.0,2.0)", "1.0.1", true)]
    [InlineData("(1.0,)", "1.0", false)]
    [InlineData("(1.0,)", "1.0.1", true)]
    [InlineData("[1.0, )", "1.0", true)]
    [InlineData("(,1.0]", "1.0", true)]
    [InlineData("(,1.0]", "1.0.1", false)]
    [InlineData("(,2.0)", "1.9", true)]
    [InlineData("(,2.0)", "2.0", false)]
    [InlineData("[1.0.0, 2.0.0)", "1.5.0", true)]
    [InlineData("[1.0]", "1.0", true)]
    [InlineData("[1.0]", "1.0.0.0", true)]
    [InlineData("[1.0]", "1.0.1", false)]
    [InlineData("[1.0]", "0.9", false)]
    public void Interval_notation(string range, string version, bool expected)
    {
        Assert.Equal(expected, In(range, version));
    }

    [Theory]
    [InlineData(">= 1.0.0", "0.9", false)]
    [InlineData(">= 1.0.0", "1.0", true)]
    [InlineData("> 1.0.0", "1.0", false)]
    [InlineData("> 1.0.0", "1.0.1", true)]
    [InlineData("<= 2.0", "2.0", true)]
    [InlineData("<= 2.0", "2.0.1", false)]
    [InlineData("< 2.0", "2.0", false)]
    [InlineData("< 2.0", "1.9", true)]
    [InlineData("= 1.0.0", "1.0.0", true)]
    [InlineData("= 1.0.0", "1.0.1", false)]
    [InlineData(">= 1.0.0 < 2.0.0", "1.5", true)]
    [InlineData(">= 1.0.0 < 2.0.0", "2.0", false)]
    [InlineData(">=1.0.0<2.0.0", "1.5", true)]
    [InlineData("(>= 1.0.0 && < 2.0.0)", "1.5", true)]
    [InlineData(">= 1.0.0 && < 2.0.0", "2.0.0", false)]
    [InlineData(">= 1.0.0-beta", "1.0.0-alpha", false)]
    public void Comparator_forms_as_written_in_assets_files(string range, string version, bool expected)
    {
        Assert.Equal(expected, In(range, version));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abc")]
    [InlineData("1.*")]
    [InlineData("*")]
    [InlineData("[1.0")]
    [InlineData("1.0]")]
    [InlineData("(1.0)")]
    [InlineData("[1.0)")]
    [InlineData("(1.0]")]
    [InlineData("[,]")]
    [InlineData("(,)")]
    [InlineData("[2.0,1.0]")]
    [InlineData("(1.0,1.0)")]
    [InlineData("[1.0,1.0)")]
    [InlineData("(1.0,1.0]")]
    [InlineData("[1.0,2.0,3.0]")]
    [InlineData("[a,b]")]
    [InlineData(">=")]
    [InlineData(">= abc")]
    [InlineData(">= 1.0 >= 2.0")]
    [InlineData("< 1.0 <= 2.0")]
    [InlineData("= 1.0 < 2.0")]
    [InlineData("=")]
    [InlineData("1.0 2.0")]
    [InlineData("1.0 && 2.0")]
    [InlineData(">= 2.0 < 1.0")]
    public void Anything_that_is_not_understood_is_rejected_not_guessed(string text)
    {
        Assert.False(NuGetVersionRange.TryParse(text, out NuGetVersionRange? range));
        Assert.Null(range);
    }

    [Fact]
    public void Null_is_rejected()
    {
        Assert.False(NuGetVersionRange.TryParse(null, out _));
    }

    [Theory]
    [InlineData("[1.0,2.0)", "[1.0.0, 2.0.0)")]
    [InlineData("1.0", "[1.0.0, )")]
    [InlineData(">= 1.0", "[1.0.0, )")]
    [InlineData("> 1.0", "(1.0.0, )")]
    [InlineData("[1.0]", "[1.0.0]")]
    [InlineData("= 1.0", "[1.0.0]")]
    [InlineData("(,1.0]", "(, 1.0.0]")]
    [InlineData("(,2.0)", "(, 2.0.0)")]
    [InlineData("(1.0,2.0]", "(1.0.0, 2.0.0]")]
    public void ToString_is_the_normalized_interval_notation(string text, string expected)
    {
        Assert.Equal(expected, Range(text).ToString());
    }

    [Fact]
    public void Normalized_text_parses_back_to_an_equivalent_range()
    {
        foreach (string text in new[] { "[1.0,2.0)", "1.0", "(1.0,)", "[1.0]", "(,1.0]", ">= 1.0 < 2.0" })
        {
            NuGetVersionRange original = Range(text);
            NuGetVersionRange again = Range(original.ToString());

            foreach (string probe in new[] { "0.5", "1.0", "1.0.1", "1.5", "2.0", "3.0" })
            {
                NuGetVersion version = NuGetVersion.Parse(probe);
                Assert.Equal(original.Contains(version), again.Contains(version));
            }
        }
    }

    [Fact]
    public void Contains_rejects_null()
    {
        Assert.Throws<ArgumentNullException>(() => Range("1.0").Contains(null!));
    }

    [Fact]
    public void The_bounds_are_exposed()
    {
        NuGetVersionRange range = Range("(1.0,2.0]");

        Assert.Equal(NuGetVersion.Parse("1.0"), range.Min);
        Assert.False(range.MinInclusive);
        Assert.Equal(NuGetVersion.Parse("2.0"), range.Max);
        Assert.True(range.MaxInclusive);
    }
}

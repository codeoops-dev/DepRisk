using DepRisk.Core.Cvss;
using Xunit;

namespace DepRisk.Core.Tests;

public class CvssV3Tests
{
    // Scores published by FIRST and widely reproduced (NVD, GitHub Advisory Database, the FIRST calculator).
    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM")]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "HIGH")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "HIGH")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, "MEDIUM")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "CRITICAL")]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5, "MEDIUM")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "CRITICAL")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "MEDIUM")]
    [InlineData("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "HIGH")]
    [InlineData("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "LOW")]
    [InlineData("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL")]
    public void Published_vectors_give_the_published_scores(string vector, double expected, string rating)
    {
        Assert.True(CvssV3.TryScore(vector, out CvssScore? score));
        Assert.Equal(expected, score!.BaseScore);
        Assert.Equal(rating, score.Rating);
        Assert.Equal(vector, score.Vector);
    }

    [Fact]
    public void The_version_comes_from_the_prefix()
    {
        Assert.True(CvssV3.TryScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", out CvssScore? v30));
        Assert.True(CvssV3.TryScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", out CvssScore? v31));

        Assert.Equal("3.0", v30!.Version);
        Assert.Equal("3.1", v31!.Version);
    }

    [Fact]
    public void Metric_order_does_not_matter_and_the_vector_is_normalized()
    {
        Assert.True(CvssV3.TryScore("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N", out CvssScore? score));

        Assert.Equal(9.8, score!.BaseScore);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score.Vector);
    }

    [Fact]
    public void Temporal_and_environmental_metrics_are_ignored()
    {
        Assert.True(CvssV3.TryScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C/CR:L/MAV:P", out CvssScore? score));

        Assert.Equal(9.8, score!.BaseScore);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("9.8")]
    [InlineData("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")]
    [InlineData("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:H")]
    [InlineData("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/:H")]
    [InlineData("CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("CVSS:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")]
    public void Unsupported_or_malformed_vectors_are_not_scored(string vector)
    {
        Assert.False(CvssV3.TryScore(vector, out CvssScore? score));
        Assert.Null(score);
    }

    [Fact]
    public void Null_is_not_scored()
    {
        Assert.False(CvssV3.TryScore(null, out _));
    }

    [Theory]
    [InlineData(0.0, "NONE")]
    [InlineData(0.1, "LOW")]
    [InlineData(3.9, "LOW")]
    [InlineData(4.0, "MEDIUM")]
    [InlineData(6.9, "MEDIUM")]
    [InlineData(7.0, "HIGH")]
    [InlineData(8.9, "HIGH")]
    [InlineData(9.0, "CRITICAL")]
    [InlineData(10.0, "CRITICAL")]
    public void Ratings_follow_the_specification_boundaries(double score, string rating)
    {
        Assert.Equal(rating, CvssV3.Rating(score));
    }

    [Theory]
    [InlineData(4.02, 4.1)]
    [InlineData(4.00, 4.0)]
    [InlineData(4.0000001, 4.0)]
    [InlineData(0.0, 0.0)]
    [InlineData(9.95, 10.0)]
    public void Roundup_rounds_up_to_one_decimal_and_ignores_float_noise(double input, double expected)
    {
        Assert.Equal(expected, CvssV3.Roundup(input));
    }

    [Fact]
    public void Scores_are_formatted_with_one_decimal_and_a_dot_whatever_the_culture()
    {
        System.Globalization.CultureInfo original = System.Globalization.CultureInfo.CurrentCulture;

        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("fa-IR");

            Assert.Equal("9.8", CvssV3.Format(9.8));
            Assert.Equal("10.0", CvssV3.Format(10));
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = original;
        }
    }
}

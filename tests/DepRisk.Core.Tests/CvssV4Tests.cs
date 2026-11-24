using System.Globalization;
using DepRisk.Core.Cvss;
using Xunit;

namespace DepRisk.Core.Tests;

public class CvssV4Tests
{
    private const string Full = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";

    private static string Format(double score) => score.ToString("0.0", CultureInfo.InvariantCulture);

    [Fact]
    public void Every_reference_vector_scores_as_the_reference_calculator_does()
    {
        Assert.True(CvssV4ReferenceVectors.Lines.Length > 200);

        foreach (string line in CvssV4ReferenceVectors.Lines)
        {
            string[] parts = line.Split(' ');

            Assert.True(CvssV4.TryScore(parts[0], out CvssScore? score), parts[0]);
            Assert.Equal(parts[1], Format(score!.BaseScore));
        }
    }

    [Theory]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "10.0", "CRITICAL")]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "0.0", "NONE")]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "9.3", "CRITICAL")]
    [InlineData("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "8.6", "HIGH")]
    public void Well_known_vectors(string vector, string expected, string rating)
    {
        Assert.True(CvssV4.TryScore(vector, out CvssScore? score));
        Assert.Equal(expected, Format(score!.BaseScore));
        Assert.Equal(rating, score.Rating);
        Assert.Equal("4.0", score.Version);
    }

    [Fact]
    public void The_vector_is_returned_in_the_canonical_base_order_without_optional_metrics()
    {
        Assert.True(CvssV4.TryScore("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N/E:P/CR:L", out CvssScore? score));

        Assert.Equal("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score!.Vector);
    }

    [Fact]
    public void Threat_environmental_and_supplemental_metrics_are_checked_but_do_not_change_the_base_score()
    {
        Assert.True(CvssV4.TryScore(Full, out CvssScore? bare));
        Assert.True(CvssV4.TryScore(Full + "/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:L/U:Red", out CvssScore? withOptional));

        Assert.Equal(bare!.BaseScore, withOptional!.BaseScore);
        Assert.Equal(bare.Vector, withOptional.Vector);
    }

    [Fact]
    public void Surrounding_whitespace_is_ignored()
    {
        Assert.True(CvssV4.TryScore("  " + Full + "\n", out CvssScore? score));
        Assert.Equal("10.0", Format(score!.BaseScore));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("CVSS:4.0")]
    [InlineData("CVSS:4.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")]
    [InlineData("cvss:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H")]          // SA missing
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/AV:N")] // duplicate
    [InlineData("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")]      // X is not a base value
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:H")]      // S only exists for MSI and MSA
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/ZZ:N")] // unknown metric
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:Q")]  // invalid optional value
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/U:Pink")]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/")]     // empty part
    [InlineData("CVSS:4.0/AV:NN/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")]     // two letters
    [InlineData("CVSS:4.0/AV/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")]
    public void A_vector_that_is_not_a_complete_valid_v4_vector_is_not_scored(string? vector)
    {
        Assert.False(CvssV4.TryScore(vector, out CvssScore? score));
        Assert.Null(score);
    }

    [Fact]
    public void The_score_does_not_depend_on_the_order_of_the_metrics()
    {
        Assert.True(CvssV4.TryScore("CVSS:4.0/VC:L/AV:P/AC:H/AT:P/PR:H/UI:A/VI:N/VA:N/SC:L/SI:L/SA:N", out CvssScore? a));
        Assert.True(CvssV4.TryScore("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N", out CvssScore? b));

        Assert.Equal(a!.BaseScore, b!.BaseScore);
        Assert.Equal(a.Vector, b.Vector);
    }

    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1", "9.8")]
    [InlineData("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.0", "9.8")]
    [InlineData(Full, "4.0", "10.0")]
    public void The_scorer_picks_the_version_from_the_vector(string vector, string version, string expected)
    {
        Assert.True(CvssScorer.TryScore(vector, out CvssScore? score));
        Assert.Equal(version, score!.Version);
        Assert.Equal(expected, Format(score.BaseScore));
    }

    [Theory]
    [InlineData("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")]
    [InlineData("AV:N/AC:L/Au:N/C:P/I:P/A:P")]
    [InlineData("nonsense")]
    [InlineData(null)]
    public void The_scorer_does_not_score_other_versions_or_garbage(string? vector)
    {
        Assert.False(CvssScorer.TryScore(vector, out CvssScore? score));
        Assert.Null(score);
    }
}

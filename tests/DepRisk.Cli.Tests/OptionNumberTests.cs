using System.Globalization;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class OptionNumberTests
{
    [Theory]
    [InlineData("5", true, 5)]
    [InlineData("+5", true, 5)]
    [InlineData(" 5 ", true, 5)]
    [InlineData("-5", true, -5)]
    [InlineData("0", true, 0)]
    [InlineData("2147483647", true, int.MaxValue)]
    [InlineData("2147483648", false, 0)]
    [InlineData("5x", false, 0)]
    [InlineData("5.0", false, 0)]
    [InlineData("1,000", false, 0)]
    [InlineData("", false, 0)]
    [InlineData("\u0665", false, 0)]
    public void TryInt_takes_a_whole_number_with_an_optional_sign_and_spaces(string text, bool ok, int expected)
    {
        Assert.Equal(ok, OptionNumber.TryInt(text, out int value));
        Assert.Equal(expected, value);
    }

    [Fact]
    public void TryInt_refuses_null()
    {
        Assert.False(OptionNumber.TryInt(null, out _));
    }

    [Theory]
    [InlineData("7", true, 7UL)]
    [InlineData("+7", true, 7UL)]
    [InlineData(" 7 ", true, 7UL)]
    [InlineData("18446744073709551615", true, ulong.MaxValue)]
    [InlineData("18446744073709551616", false, 0UL)]
    [InlineData("-1", false, 0UL)]
    [InlineData("7x", false, 0UL)]
    public void TryULong_takes_a_whole_number_from_zero_up(string text, bool ok, ulong expected)
    {
        Assert.Equal(ok, OptionNumber.TryULong(text, out ulong value));
        Assert.Equal(expected, value);
    }

    [Fact]
    public void The_current_culture_does_not_change_what_is_accepted()
    {
        CultureInfo original = CultureInfo.CurrentCulture;
        CultureInfo odd = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        odd.NumberFormat.NegativeSign = "neg";
        odd.NumberFormat.PositiveSign = "pos";

        try
        {
            CultureInfo.CurrentCulture = odd;

            // Under this culture the plain sign is not a sign and the culture's own words are: the commands must not follow it.
            Assert.False(int.TryParse("-5", NumberStyles.Integer, CultureInfo.CurrentCulture, out _));
            Assert.True(int.TryParse("neg5", NumberStyles.Integer, CultureInfo.CurrentCulture, out _));

            Assert.True(OptionNumber.TryInt("-5", out int minusFive));
            Assert.Equal(-5, minusFive);
            Assert.True(OptionNumber.TryInt("+5", out int five));
            Assert.Equal(5, five);
            Assert.False(OptionNumber.TryInt("neg5", out _));
            Assert.False(OptionNumber.TryULong("pos5", out _));
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }
}

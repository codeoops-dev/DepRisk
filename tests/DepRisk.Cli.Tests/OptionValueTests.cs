using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class OptionValueTests
{
    [Fact]
    public void Read_returns_the_next_argument_and_moves_the_index_to_it()
    {
        string[] args = ["--out", "file.json", "--strict"];
        int index = 0;

        Assert.Equal("file.json", OptionValue.Read(args, ref index, "--out"));
        Assert.Equal(1, index);
    }

    [Fact]
    public void A_missing_value_is_an_input_error_that_names_the_option()
    {
        string[] args = ["--out"];
        int index = 0;

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => OptionValue.Read(args, ref index, "--out"));

        Assert.Equal("option '--out' needs a value.", error.Message);
    }

    [Theory]
    [InlineData("--format", "json", true, 1)]
    [InlineData("-f", "json", true, 1)]
    [InlineData("--format=json", null, true, 0)]
    [InlineData("--format=", null, true, 0)]
    [InlineData("--formats", null, false, 0)]
    [InlineData("--format-x=1", null, false, 0)]
    [InlineData("-o", null, false, 0)]
    [InlineData("format", null, false, 0)]
    public void TryValue_matches_the_long_name_the_short_name_and_the_equals_form_only(string arg, string? next, bool matched, int moved)
    {
        string[] args = next is null ? [arg] : [arg, next];
        int index = 0;

        bool result = OptionValue.TryValue(args, ref index, arg, "--format", "-f", out string? value);

        Assert.Equal(matched, result);
        Assert.Equal(moved, index);

        if (matched)
        {
            Assert.Equal(arg.Contains('=') ? arg[(arg.IndexOf('=') + 1)..] : next, value);
        }
        else
        {
            Assert.Null(value);
        }
    }

    [Fact]
    public void An_option_without_a_short_name_does_not_match_a_dash_letter()
    {
        int index = 0;

        Assert.False(OptionValue.TryValue(["-s", "x"], ref index, "-s", "--source", null, out _));
    }

    [Fact]
    public void TryValue_with_a_missing_value_is_an_input_error_naming_the_form_that_was_written()
    {
        int index = 0;

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => OptionValue.TryValue(["-f"], ref index, "-f", "--format", "-f", out _));

        Assert.Equal("option '-f' needs a value.", error.Message);
    }
}

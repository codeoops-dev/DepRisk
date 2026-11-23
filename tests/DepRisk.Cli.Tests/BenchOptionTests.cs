using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// The numeric options of <c>bench</c> and <c>bench calibrate</c> read numbers like every other command (S21), and the order in which they
/// are checked is unchanged. The benchmark manifest <c>x</c> does not exist: an option that is accepted gets as far as that error.
/// </summary>
public sealed class BenchOptionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-benchopt-" + Guid.NewGuid().ToString("N"));

    public BenchOptionTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private (int Code, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, error.ToString());
    }

    [Theory]
    [InlineData("--samples", "+300")]
    [InlineData("--samples", " 300 ")]
    [InlineData("--seed", "+5")]
    [InlineData("--seed", " 7")]
    [InlineData("--bootstrap", "+5")]
    [InlineData("--bootstrap", " 5 ")]
    [InlineData("--timeout", "+10")]
    [InlineData("--timeout", " 10 ")]
    public void A_sign_or_spaces_are_accepted_as_in_the_other_commands(string option, string value)
    {
        (int code, string error) = Run("bench", "--cases", "x", option, value);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("benchmark manifest not found", error);
    }

    [Theory]
    [InlineData("--min-count", "+2")]
    [InlineData("--min-count", " 2 ")]
    [InlineData("--timeout", "+5")]
    [InlineData("--timeout", " 5 ")]
    public void The_same_holds_for_bench_calibrate(string option, string value)
    {
        (int code, string error) = Run("bench", "calibrate", "--cases", "x", "--out", "o.json", option, value);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("benchmark manifest not found", error);
    }

    [Theory]
    [InlineData("--samples", "abc", "--samples must be a whole number from")]
    [InlineData("--samples", "-300", "--samples must be a whole number from")]
    [InlineData("--seed", "-5", "--seed must be a whole number from 0 to 18446744073709551615.")]
    [InlineData("--seed", "18446744073709551616", "--seed must be a whole number from 0 to 18446744073709551615.")]
    [InlineData("--bootstrap", "-1", "--bootstrap must be a whole number from 0 (off) to")]
    [InlineData("--bootstrap", "abc", "--bootstrap must be a whole number from 0 (off) to")]
    [InlineData("--timeout", "0", "--timeout must be a whole number of seconds from 1 to")]
    [InlineData("--timeout", "-5", "--timeout must be a whole number of seconds from 1 to")]
    [InlineData("--rank-by", "bogus", "--rank-by must be one of:")]
    public void Values_that_are_not_valid_are_still_refused_with_the_same_messages(string option, string value, string message)
    {
        (int code, string error) = Run("bench", "--cases", "x", option, value);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains(message, error);
    }

    [Theory]
    [InlineData("--min-count", "0", "--min-count must be a whole number from 1 to")]
    [InlineData("--min-count", "-2", "--min-count must be a whole number from 1 to")]
    [InlineData("--timeout", "-5", "--timeout must be a whole number of seconds from 1 to")]
    public void Calibrate_values_that_are_not_valid_are_still_refused(string option, string value, string message)
    {
        (int code, string error) = Run("bench", "calibrate", "--cases", "x", "--out", "o.json", option, value);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains(message, error);
    }

    [Fact]
    public void The_options_are_checked_in_the_same_order_as_before()
    {
        Assert.Contains("--samples must", Run("bench", "--cases", "x", "--samples", "abc", "--rank-by", "bogus").Err);
        Assert.Contains("--seed must", Run("bench", "--cases", "x", "--seed", "abc", "--rank-by", "bogus").Err);
        Assert.Contains("--rank-by must", Run("bench", "--cases", "x", "--rank-by", "bogus", "--bootstrap", "-1").Err);
        Assert.Contains("--bootstrap must", Run("bench", "--cases", "x", "--risk-params", "nofile.json", "--bootstrap", "-1").Err);
        Assert.DoesNotContain("manifest not found", Run("bench", "--cases", "x", "--risk-params", "nofile.json").Err);
    }
}

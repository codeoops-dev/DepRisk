using DepRisk.Core;
using DepRisk.Core.Risk;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class RiskOptionArgsTests
{
    private static RiskOptionArgs Parse(int defaultSamples, params string[] args)
    {
        RiskOptionArgs risk = new(defaultSamples);

        for (int i = 0; i < args.Length; i++)
        {
            Assert.True(risk.TryRead(args, ref i, args[i]), $"'{args[i]}' was not read");
        }

        return risk;
    }

    [Fact]
    public void Nothing_given_means_the_default_samples_a_random_seed_and_the_mean()
    {
        RiskOptionArgs risk = Parse(1234);

        Assert.False(risk.AnyGiven);
        risk.Validate();
        var request = risk.Build(TestContext.For(Path.GetTempPath()));

        Assert.Equal(1234, request.Samples);
        Assert.Null(request.Seed);
        Assert.Equal("mean", request.RankBy);
    }

    [Fact]
    public void The_four_options_are_read_in_both_forms_and_mark_the_set_as_given()
    {
        RiskOptionArgs risk = Parse(5000, "--samples=300", "--seed", "42", "--rank-by", "cvar");

        Assert.True(risk.AnyGiven);
        risk.Validate();
        var request = risk.Build(TestContext.For(Path.GetTempPath()));

        Assert.Equal(300, request.Samples);
        Assert.Equal(42UL, request.Seed);
        Assert.Equal("cvar95", request.RankBy);
    }

    [Fact]
    public void Other_options_are_not_read()
    {
        RiskOptionArgs risk = new(5000);
        int index = 0;

        Assert.False(risk.TryRead(["--format", "json"], ref index, "--format"));
        Assert.False(risk.AnyGiven);
    }

    [Fact]
    public void Validation_goes_samples_then_seed_then_statistic()
    {
        InvalidInputException samples = Assert.Throws<InvalidInputException>(() => Parse(5000, "--samples", "abc", "--seed", "x", "--rank-by", "bogus").Validate());
        Assert.Contains("--samples must be a whole number from", samples.Message);

        InvalidInputException seed = Assert.Throws<InvalidInputException>(() => Parse(5000, "--seed", "x", "--rank-by", "bogus").Validate());
        Assert.Contains("--seed must be a whole number from 0 to 18446744073709551615.", seed.Message);

        InvalidInputException rankBy = Assert.Throws<InvalidInputException>(() => Parse(5000, "--rank-by", "bogus").Validate());
        Assert.Contains("--rank-by must be one of:", rankBy.Message);
    }

    [Fact]
    public void Samples_outside_the_range_are_refused()
    {
        Assert.Throws<InvalidInputException>(() => Parse(5000, "--samples", (RiskModel.MinSamples - 1).ToString()).Validate());
        Assert.Throws<InvalidInputException>(() => Parse(5000, "--samples", (RiskModel.MaxSamples + 1).ToString()).Validate());
        Parse(5000, "--samples", RiskModel.MinSamples.ToString()).Validate();
        Parse(5000, "--samples", RiskModel.MaxSamples.ToString()).Validate();
    }

    [Fact]
    public void A_missing_parameter_file_is_an_input_error_only_when_the_request_is_built()
    {
        RiskOptionArgs risk = Parse(5000, "--risk-params", "no-such-file.json");

        risk.Validate();

        Assert.Throws<InvalidInputException>(() => risk.Build(TestContext.For(Path.GetTempPath())));
    }
}

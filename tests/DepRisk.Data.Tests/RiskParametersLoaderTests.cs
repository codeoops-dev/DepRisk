using DepRisk.Core;
using DepRisk.Core.Risk;
using DepRisk.Data.Risk;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class RiskParametersLoaderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-riskp-" + Guid.NewGuid().ToString("N"));

    public RiskParametersLoaderTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Put(string json)
    {
        string path = Path.Combine(_root, "params.json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void The_defaults_are_labeled_uncalibrated_and_have_a_stable_digest()
    {
        LoadedRiskParameters a = RiskParametersLoader.Defaults();
        LoadedRiskParameters b = RiskParametersLoader.Defaults();

        Assert.Equal("uncalibrated-defaults", a.Calibration);
        Assert.Equal(a.ParametersDigest, b.ParametersDigest);
        Assert.True(Digest.IsSha256Hex(a.ParametersDigest));
        Assert.Equal(RiskParameters.Default, a.Parameters);
    }

    [Fact]
    public void A_file_replaces_only_the_numbers_it_names_and_is_labeled_custom()
    {
        LoadedRiskParameters loaded = RiskParametersLoader.Load(Put("""
            { "schemaVersion": 1,
              "reach": { "reachable": { "alpha": 19, "beta": 1 } },
              "exploit": { "kevMean": 0.9 },
              "impact": { "low": 5, "high": 10 } }
            """));

        Assert.Equal("custom", loaded.Calibration);
        Assert.Equal(new BetaParams(19, 1), loaded.Parameters.Reach.Reachable);
        Assert.Equal(RiskParameters.Default.Reach.Unreachable, loaded.Parameters.Reach.Unreachable);
        Assert.Equal(0.9, loaded.Parameters.Exploit.KevMean);
        Assert.Equal(RiskParameters.Default.Exploit.EpssConcentration, loaded.Parameters.Exploit.EpssConcentration);
        Assert.Equal(5, loaded.Parameters.Impact.Low);
        Assert.NotEqual(RiskParametersLoader.Defaults().ParametersDigest, loaded.ParametersDigest);
    }

    [Fact]
    public void A_file_that_only_has_a_version_is_the_defaults_with_a_custom_label()
    {
        LoadedRiskParameters loaded = RiskParametersLoader.Load(Put("""{ "schemaVersion": 1 }"""));

        Assert.Equal(RiskParameters.Default, loaded.Parameters);
        Assert.Equal(RiskParametersLoader.Defaults().ParametersDigest, loaded.ParametersDigest);
        Assert.Equal("custom", loaded.Calibration);
    }

    [Theory]
    [InlineData("{ nope", "not valid JSON")]
    [InlineData("[]", "missing 'schemaVersion'")]
    [InlineData("""{ "schemaVersion": 2 }""", "unsupported schemaVersion 2")]
    [InlineData("""{ "schemaVersion": 1, "reachh": {} }""", "unknown property 'reachh'")]
    [InlineData("""{ "schemaVersion": 1, "reach": { "reachabel": { "alpha": 1, "beta": 1 } } }""", "unknown property 'reachabel'")]
    [InlineData("""{ "schemaVersion": 1, "exploit": { "kevmean": 0.5 } }""", "unknown property 'kevmean'")]
    [InlineData("""{ "schemaVersion": 1, "impact": { "hi": 5 } }""", "unknown property 'hi'")]
    [InlineData("""{ "schemaVersion": 1, "reach": { "reachable": { "alpha": 1 } } }""", "needs both 'alpha' and 'beta'")]
    [InlineData("""{ "schemaVersion": 1, "reach": { "reachable": { "alpha": 1, "beta": 1, "gamma": 2 } } }""", "unknown property 'gamma'")]
    [InlineData("""{ "schemaVersion": 1, "reach": 5 }""", "'reach' must be an object")]
    [InlineData("""{ "schemaVersion": 1, "exploit": { "kevMean": "high" } }""", "'exploit.kevMean' must be a number")]
    [InlineData("""{ "schemaVersion": 1, "reach": { "reachable": { "alpha": 0, "beta": 1 } } }""", "reach.reachable")]
    [InlineData("""{ "schemaVersion": 1, "exploit": { "kevMean": 1 } }""", "KEV means")]
    [InlineData("""{ "schemaVersion": 1, "impact": { "low": 9, "high": 3 } }""", "low <= high")]
    [InlineData("""{ "schemaVersion": 1, "impact": { "criticalSeverityFactor": 2 } }""", "severity factors")]
    public void A_bad_file_is_rejected_naming_the_problem_and_never_run_with_the_defaults_instead(string json, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => RiskParametersLoader.Load(Put(json)));

        Assert.Contains("params.json", error.Message);
        Assert.Contains(expected, error.Message);
    }

    [Fact]
    public void A_missing_or_oversized_file_is_reported()
    {
        Assert.Contains("not found", Assert.Throws<InvalidInputException>(() => RiskParametersLoader.Load(Path.Combine(_root, "nope.json"))).Message);

        string big = Put("{}");
        using (FileStream stream = File.OpenWrite(big))
        {
            stream.SetLength(RiskParametersLoader.MaxFileBytes + 1);
        }

        Assert.Contains("larger than 1 MB", Assert.Throws<InvalidInputException>(() => RiskParametersLoader.Load(big)).Message);
    }

    [Fact]
    public void Control_characters_in_an_unknown_property_name_are_not_echoed()
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => RiskParametersLoader.Load(Put("{ \"schemaVersion\": 1, \"a\\u001b[31m\": 1 }")));

        Assert.False(error.Message.Contains('\u001b'));
    }
}

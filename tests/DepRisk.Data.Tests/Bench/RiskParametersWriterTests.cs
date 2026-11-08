using DepRisk.Core;
using DepRisk.Core.Risk;
using DepRisk.Data.Risk;
using Xunit;

namespace DepRisk.Data.Tests.Bench;

public sealed class RiskParametersWriterTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("deprisk-params-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Save(string json)
    {
        string path = Path.Combine(_dir, "p.json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void A_written_file_loads_back_to_the_same_parameters_and_digest()
    {
        RiskParameters custom = RiskParameters.Default with { Reach = RiskParameters.Default.Reach with { Reachable = new BetaParams(21, 6) } };

        LoadedRiskParameters loaded = RiskParametersLoader.Load(Save(RiskParametersWriter.Write(custom, "fitted on a test set")));

        Assert.Equal(custom, loaded.Parameters);
        Assert.Equal(Digest.Sha256Hex(custom.Canonical()), loaded.ParametersDigest);
        Assert.Equal("custom", loaded.Calibration);
        Assert.Equal("fitted on a test set", loaded.Provenance);
    }

    [Fact]
    public void The_defaults_survive_a_round_trip_bit_for_bit()
    {
        LoadedRiskParameters loaded = RiskParametersLoader.Load(Save(RiskParametersWriter.Write(RiskParameters.Default, "defaults")));

        Assert.Equal(RiskParameters.Default, loaded.Parameters);
        Assert.Equal(RiskParametersLoader.Defaults().ParametersDigest, loaded.ParametersDigest);
    }

    [Fact]
    public void The_provenance_is_not_part_of_the_parameters_digest()
    {
        LoadedRiskParameters a = RiskParametersLoader.Load(Save(RiskParametersWriter.Write(RiskParameters.Default, "one note")));
        LoadedRiskParameters b = RiskParametersLoader.Load(Save(RiskParametersWriter.Write(RiskParameters.Default, "another note")));

        Assert.Equal(a.ParametersDigest, b.ParametersDigest);
    }

    [Fact]
    public void The_text_is_readable_json_with_lf_line_endings_and_no_escaped_quotes()
    {
        string json = RiskParametersWriter.Write(RiskParameters.Default, "made by 'bench calibrate'");

        Assert.DoesNotContain("\r", json);
        Assert.DoesNotContain("\\u0027", json);
        Assert.Contains("\"provenance\": \"made by 'bench calibrate'\"", json);
        Assert.EndsWith("}\n", json);
    }

    [Fact]
    public void A_provenance_that_is_empty_too_long_non_text_or_has_control_characters_is_refused_on_load()
    {
        static string With(string provenance) => $$"""{ "schemaVersion": 1, "provenance": {{provenance}} }""";

        foreach (string bad in new[] { "\"\"", "1", "null", "\"a\\u001b[31mb\"", "\"" + new string('x', RiskParametersWriter.MaxProvenanceLength + 1) + "\"" })
        {
            InvalidInputException ex = Assert.Throws<InvalidInputException>(() => RiskParametersLoader.Load(Save(With(bad))));
            Assert.Contains("'provenance' must be text", ex.Message);
        }
    }

    [Fact]
    public void A_newline_in_the_provenance_is_allowed_and_unknown_properties_are_still_refused()
    {
        Assert.Equal("a\nb", RiskParametersLoader.Load(Save("""{ "schemaVersion": 1, "provenance": "a\nb" }""")).Provenance);
        Assert.Throws<InvalidInputException>(() => RiskParametersLoader.Load(Save("""{ "schemaVersion": 1, "provenence": "typo" }""")));
    }

    [Fact]
    public void Parameters_that_do_not_validate_are_not_written()
    {
        RiskParameters bad = RiskParameters.Default with { Reach = RiskParameters.Default.Reach with { Reachable = new BetaParams(0, 1) } };

        Assert.Throws<InvalidOperationException>(() => RiskParametersWriter.Write(bad, "x"));
    }
}

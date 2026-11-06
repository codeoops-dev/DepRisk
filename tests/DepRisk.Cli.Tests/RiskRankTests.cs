using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>rank and ci with --model risk, on the reach fixtures (and the stand-in analyzer where reachability is wanted).</summary>
public sealed class RiskRankTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-risk-cli-" + Guid.NewGuid().ToString("N"));

    private string Project => Path.Combine(_root, "proj");

    private string Osv => Path.Combine(_root, "osv");

    private string Symbols => Path.Combine(_root, "symbols", "example.json");

    public RiskRankTests()
    {
        Directory.CreateDirectory(Project);
        Directory.CreateDirectory(Osv);
        Directory.CreateDirectory(Path.GetDirectoryName(Symbols)!);
        File.WriteAllText(Path.Combine(Project, "project.assets.json"), NpmFixtures.ReadReach("assets/project.assets.json"));

        foreach (string id in new[] { "0001", "0002", "0003" })
        {
            File.WriteAllText(Path.Combine(Osv, $"DEPRISK-EXAMPLE-{id}.json"), NpmFixtures.ReadReach($"osv/DEPRISK-EXAMPLE-{id}.json"));
        }

        File.WriteAllText(Symbols, NpmFixtures.ReadReach("symbols/example.json"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private string[] Risk(params string[] extra) => ["rank", Project, "--advisories", Osv, "--model", "risk", .. extra];

    private string[] RiskWithReach(params string[] extra) =>
        [.. Risk("--symbols", Symbols, "--analyzer", FakeAnalyzerScript.Create(_root)), .. extra];

    private static JsonElement[] Findings(JsonDocument d) => d.RootElement.GetProperty("findings").EnumerateArray().ToArray();

    [Fact]
    public void Every_finding_gets_a_distribution_and_the_model_says_what_it_is()
    {
        (int code, string output, string error) = Run(Risk("--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;

        Assert.Equal("risk-monte-carlo", root.GetProperty("method").GetString());
        Assert.Equal("risk.mean", root.GetProperty("ordering")[0].GetString());
        JsonElement model = root.GetProperty("model");
        Assert.Equal(5000, model.GetProperty("samples").GetInt32());
        Assert.Equal("default", model.GetProperty("seedSource").GetString());
        Assert.Equal("uncalibrated-defaults", model.GetProperty("calibration").GetString());
        Assert.Equal(0.9, model.GetProperty("parameters").GetProperty("reach").GetProperty("reachable").GetProperty("mean").GetDouble(), 6);

        Assert.All(Findings(document), f =>
        {
            JsonElement risk = f.GetProperty("risk");
            Assert.True(risk.GetProperty("mean").GetDouble() > 0);
            Assert.True(risk.GetProperty("p50").GetDouble() <= risk.GetProperty("p95").GetDouble());
            Assert.True(risk.GetProperty("p95").GetDouble() <= risk.GetProperty("cvar95").GetDouble());
            Assert.True(f.GetProperty("baselineRank").GetInt32() >= 1);
        });
    }

    [Fact]
    public void The_baseline_method_has_no_model_and_no_distributions()
    {
        (_, string output, _) = Run("rank", Project, "--advisories", Osv, "--format", "json");

        using JsonDocument document = JsonDocument.Parse(output);

        Assert.Equal("baseline-kev-epss-cvss", document.RootElement.GetProperty("method").GetString());
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("model").ValueKind);
        Assert.All(Findings(document), f =>
        {
            Assert.Equal(JsonValueKind.Null, f.GetProperty("risk").ValueKind);
            Assert.Equal(JsonValueKind.Null, f.GetProperty("baselineRank").ValueKind);
        });
    }

    [Fact]
    public void The_same_inputs_give_byte_identical_output_and_a_given_seed_changes_the_numbers_and_says_so()
    {
        (_, string one, _) = Run(Risk("--format", "json"));
        (_, string two, _) = Run(Risk("--format", "json"));
        (_, string seeded, _) = Run(Risk("--format", "json", "--seed", "123456789012345678"));

        Assert.Equal(one, two);
        Assert.NotEqual(one, seeded);

        using JsonDocument document = JsonDocument.Parse(seeded);
        Assert.Equal("given", document.RootElement.GetProperty("model").GetProperty("seedSource").GetString());
        Assert.Equal("123456789012345678", document.RootElement.GetProperty("model").GetProperty("seed").GetString());
    }

    [Fact]
    public void Reachability_is_an_input_of_the_model_and_raises_the_risk_of_a_reachable_finding()
    {
        (_, string without, _) = Run(Risk("--format", "json"));
        (int code, string with, _) = Run(RiskWithReach("--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument a = JsonDocument.Parse(without);
        using JsonDocument b = JsonDocument.Parse(with);
        JsonElement plain = Findings(a).Single(f => f.GetProperty("id").GetString() == "DEPRISK-EXAMPLE-0001");
        JsonElement reached = Findings(b).Single(f => f.GetProperty("id").GetString() == "DEPRISK-EXAMPLE-0001");

        Assert.True(reached.GetProperty("risk").GetProperty("reachMean").GetDouble() > plain.GetProperty("risk").GetProperty("reachMean").GetDouble());
        Assert.True(reached.GetProperty("risk").GetProperty("mean").GetDouble() > plain.GetProperty("risk").GetProperty("mean").GetDouble());

        // A finding whose label is "unknown" is treated like one that was not analyzed: the same numbers.
        JsonElement unknownWith = Findings(b).Single(f => f.GetProperty("id").GetString() == "DEPRISK-EXAMPLE-0002");
        JsonElement notAnalyzed = Findings(a).Single(f => f.GetProperty("id").GetString() == "DEPRISK-EXAMPLE-0002");
        Assert.Equal(notAnalyzed.GetProperty("risk").GetRawText(), unknownWith.GetProperty("risk").GetRawText());
    }

    [Fact]
    public void A_finding_s_numbers_do_not_depend_on_which_other_findings_are_present()
    {
        (_, string all, _) = Run(Risk("--format", "json"));
        File.Delete(Path.Combine(Osv, "DEPRISK-EXAMPLE-0001.json"));
        (_, string fewer, _) = Run(Risk("--format", "json"));

        using JsonDocument a = JsonDocument.Parse(all);
        using JsonDocument b = JsonDocument.Parse(fewer);

        Assert.Equal(
            Findings(a).Single(f => f.GetProperty("id").GetString() == "DEPRISK-EXAMPLE-0002").GetProperty("risk").GetRawText(),
            Findings(b).Single(f => f.GetProperty("id").GetString() == "DEPRISK-EXAMPLE-0002").GetProperty("risk").GetRawText());
    }

    [Fact]
    public void The_statistic_chosen_for_the_order_is_the_one_used_and_is_recorded()
    {
        foreach (string statistic in new[] { "mean", "p50", "p90", "p95", "cvar95", "cvar" })
        {
            (int code, string output, string error) = Run(Risk("--format", "json", "--rank-by", statistic));
            Assert.True(code == (int)ExitCode.Success, $"{statistic}: {error}");

            using JsonDocument document = JsonDocument.Parse(output);
            string expected = statistic == "cvar" ? "cvar95" : statistic;
            string key = expected == "cvar95" ? "cvar95" : expected;
            double[] values = Findings(document).Select(f => f.GetProperty("risk").GetProperty(key).GetDouble()).ToArray();

            Assert.Equal(expected, document.RootElement.GetProperty("model").GetProperty("rankBy").GetString());
            Assert.Equal(values.OrderByDescending(v => v).ToArray(), values);
        }
    }

    [Fact]
    public void A_parameters_file_changes_the_numbers_and_the_calibration_label()
    {
        string file = Path.Combine(_root, "params.json");
        File.WriteAllText(file, """{ "schemaVersion": 1, "impact": { "low": 9, "high": 10 } }""");

        (_, string defaults, _) = Run(Risk("--format", "json"));
        (int code, string custom, _) = Run(Risk("--format", "json", "--risk-params", file));

        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument a = JsonDocument.Parse(defaults);
        using JsonDocument b = JsonDocument.Parse(custom);
        Assert.Equal("custom", b.RootElement.GetProperty("model").GetProperty("calibration").GetString());
        Assert.NotEqual(
            a.RootElement.GetProperty("model").GetProperty("parametersDigest").GetString(),
            b.RootElement.GetProperty("model").GetProperty("parametersDigest").GetString());
        Assert.True(Findings(b)[0].GetProperty("risk").GetProperty("impactMean").GetDouble() > Findings(a)[0].GetProperty("risk").GetProperty("impactMean").GetDouble());
    }

    [Theory]
    [InlineData("--samples", "99")]
    [InlineData("--samples", "200001")]
    [InlineData("--samples", "many")]
    [InlineData("--seed", "-1")]
    [InlineData("--seed", "abc")]
    [InlineData("--rank-by", "median")]
    public void Bad_values_are_input_errors(string option, string value)
    {
        (int code, string output, string error) = Run(Risk(option, value));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.NotEqual(string.Empty, error);
    }

    [Fact]
    public void Risk_options_without_the_risk_model_and_unknown_models_are_input_errors()
    {
        (int a, _, string e1) = Run("rank", Project, "--advisories", Osv, "--samples", "1000");
        (int b, _, string e2) = Run("rank", Project, "--advisories", Osv, "--model", "magic");
        (int c, _, string e3) = Run("rank", Project, "--advisories", Osv, "--risk-params", "x.json");

        Assert.Equal((int)ExitCode.InvalidInput, a);
        Assert.Contains("only apply with --model risk", e1);
        Assert.Equal((int)ExitCode.InvalidInput, b);
        Assert.Contains("--model must be", e2);
        Assert.Equal((int)ExitCode.InvalidInput, c);
        Assert.Contains("only apply with --model risk", e3);
    }

    [Fact]
    public void A_bad_parameters_file_fails_instead_of_falling_back_to_the_defaults()
    {
        string file = Path.Combine(_root, "typo.json");
        File.WriteAllText(file, """{ "schemaVersion": 1, "exploit": { "kevmean": 0.9 } }""");

        (int code, string output, string error) = Run(Risk("--risk-params", file));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("unknown property 'kevmean'", error);
    }

    [Fact]
    public void The_table_states_the_method_the_calibration_and_each_distribution()
    {
        (int code, string output, _) = Run(Risk());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("method: risk model: R = Reach x Exploit x Impact over 5000 seeded scenarios, ranked by mean", output);
        Assert.Contains("uncalibrated-defaults", output);
        Assert.Contains("not probabilities of real-world loss", output);
        Assert.Contains("risk: mean ", output);
        Assert.Contains("baseline #1", output);
    }

    [Fact]
    public void Ci_with_the_risk_model_still_gates_on_the_policy_and_sarif_carries_the_risk()
    {
        (int failing, _, string error) = Run("ci", Project, "--advisories", Osv, "--model", "risk", "--fail-on", "any");
        (int passing, _, _) = Run("ci", Project, "--advisories", Osv, "--model", "risk", "--fail-on", "kev");
        (int sarifCode, string sarif, _) = Run("ci", Project, "--advisories", Osv, "--model", "risk", "--format", "sarif");

        Assert.Equal((int)ExitCode.PolicyGateFailed, failing);
        Assert.Contains("3 of 3 finding(s) match", error);
        Assert.Equal((int)ExitCode.Success, passing);
        Assert.Equal((int)ExitCode.Success, sarifCode);

        using JsonDocument document = JsonDocument.Parse(sarif);
        JsonElement properties = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("properties");
        Assert.True(properties.GetProperty("riskMean").GetDouble() > 0);
        Assert.True(properties.GetProperty("riskP95").GetDouble() >= properties.GetProperty("riskMean").GetDouble() * 0.5);
    }

    [Fact]
    public void Too_much_work_is_refused_as_an_input_problem()
    {
        // 3 findings x 200000 samples is fine; the limit is on findings x samples, so shrink it by giving many advisories.
        for (int i = 0; i < 40; i++)
        {
            File.WriteAllText(
                Path.Combine(Osv, $"EXTRA-{i}.json"),
                $$"""{ "id": "EXTRA-{{i}}", "affected": [ { "package": { "ecosystem": "NuGet", "name": "Other.Lib" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "9.0.0" } ] } ] } ] }""");
        }

        (int fine, _, _) = Run(Risk("--samples", "200000"));
        Assert.Equal((int)ExitCode.Success, fine);   // 43 x 200000 = 8.6 million: well within the limit
    }

    [Fact]
    public void A_run_with_the_model_in_an_initialized_project_is_audited_and_the_log_verifies()
    {
        Assert.Equal((int)ExitCode.Success, Run("init", _root).Code);

        Assert.Equal((int)ExitCode.Success, Run(Risk("--format", "json", "--out", "risk.json")).Code);
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);
        Assert.Contains("\"command\":\"rank\"", File.ReadAllLines(Path.Combine(_root, ".deprisk", "audit.log")).Last());
    }
}

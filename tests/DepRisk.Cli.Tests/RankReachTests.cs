using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>rank and ci with reachability (--symbols), using the reach fixtures and a stand-in analyzer.</summary>
public sealed class RankReachTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-rank-reach-" + Guid.NewGuid().ToString("N"));

    private string Project => Path.Combine(_root, "proj");

    private string Osv => Path.Combine(_root, "osv");

    private string Symbols => Path.Combine(_root, "symbols", "example.json");

    public RankReachTests()
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

    private string[] WithReach(string command, params string[] extra) =>
        [command, Project, "--advisories", Osv, "--symbols", Symbols, "--analyzer", FakeAnalyzerScript.Create(_root), .. extra];

    private string[] WithoutReach(string command, params string[] extra) => [command, Project, "--advisories", Osv, .. extra];

    [Fact]
    public void Rank_adds_a_verdict_to_every_finding_and_does_not_change_the_order()
    {
        (_, string plain, _) = Run(WithoutReach("rank", "--format", "json"));
        (int code, string reached, string error) = Run(WithReach("rank", "--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument without = JsonDocument.Parse(plain);
        using JsonDocument with = JsonDocument.Parse(reached);

        string[] orderWithout = without.RootElement.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("id").GetString()!).ToArray();
        string[] orderWith = with.RootElement.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("id").GetString()!).ToArray();
        Assert.Equal(orderWithout, orderWith);

        Assert.All(without.RootElement.GetProperty("findings").EnumerateArray(), f => Assert.Equal(JsonValueKind.Null, f.GetProperty("reachability").ValueKind));
        Assert.Equal(JsonValueKind.Null, without.RootElement.GetProperty("reach").ValueKind);

        JsonElement first = with.RootElement.GetProperty("findings")[0];
        Assert.Equal("DEPRISK-EXAMPLE-0001", first.GetProperty("id").GetString());
        Assert.Equal("reachable", first.GetProperty("reachability").GetProperty("label").GetString());
        Assert.Equal("static-path", first.GetProperty("reachability").GetProperty("reason").GetString());
        Assert.Equal("Newtonsoft.Json.JsonConvert.DeserializeObject", first.GetProperty("reachability").GetProperty("symbol").GetString());

        JsonElement reach = with.RootElement.GetProperty("reach");
        Assert.Equal("deprisk-reach", reach.GetProperty("analyzer").GetProperty("name").GetString());
        Assert.Equal(1, reach.GetProperty("summary").GetProperty("reachable").GetInt32());
        Assert.Equal(2, reach.GetProperty("summary").GetProperty("unknown").GetInt32());
        Assert.DoesNotContain(_root, reached);
    }

    [Fact]
    public void Rank_table_shows_the_reachability_of_each_finding()
    {
        (int code, string output, _) = Run(WithReach("rank"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("it does not change the order", output);
        Assert.Contains("1 reachable, 0 possibly reachable, 2 unknown, 0 unreachable", output);
        Assert.Contains("reachability: reachable (a call path exists; via Newtonsoft.Json.JsonConvert.DeserializeObject)", output);
        Assert.Contains("reachability: unknown (transitive dependency", output);
        Assert.Contains("reachability: unknown (no symbol list for this advisory", output);
        Assert.Contains("not exploitability", output);
    }

    [Fact]
    public void Without_symbols_rank_says_how_to_get_reachability()
    {
        (_, string output, _) = Run(WithoutReach("rank"));

        Assert.Contains("(add --symbols for reachability)", output);
        Assert.DoesNotContain("reachability: reachable", output);
    }

    [Theory]
    [InlineData("reachable", 1, 1)]
    [InlineData("possibly-reachable", 0, 0)]
    [InlineData("reach-unknown", 1, 2)]
    [InlineData("unreachable", 0, 0)]
    [InlineData("not-unreachable", 1, 3)]
    public void Ci_gates_on_reachability(string policy, int exitCode, int matching)
    {
        (int code, _, string error) = Run(WithReach("ci", "--fail-on", policy, "--format", "json"));

        Assert.Equal(exitCode, code);

        if (exitCode == 1)
        {
            Assert.Contains($"{matching} of 3 finding(s) match", error);
        }
        else
        {
            Assert.Contains("PASSED", error);
        }
    }

    [Fact]
    public void The_gate_names_the_reachability_of_the_findings_it_stops_on()
    {
        (_, _, string error) = Run(WithReach("ci", "--fail-on", "reachable"));

        Assert.Contains("DEPRISK-EXAMPLE-0001  Newtonsoft.Json 12.0.1  [reach: reachable]", error);
    }

    [Fact]
    public void A_policy_with_reachability_terms_needs_symbols_instead_of_silently_matching_nothing()
    {
        (int code, string output, string error) = Run(WithoutReach("ci", "--fail-on", "kev&reachable"));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("need --symbols", error);
    }

    [Fact]
    public void Reachability_options_without_symbols_are_rejected()
    {
        (int code, _, string error) = Run(WithoutReach("rank", "--analyzer", "x"));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("only apply together with --symbols", error);
    }

    [Theory]
    [InlineData("--timeout", "0")]
    [InlineData("--entrypoints", "everything")]
    [InlineData("--entrypoint", "Run")]
    public void Bad_reachability_values_are_input_errors_for_rank_too(string option, string value)
    {
        (int code, _, _) = Run(WithReach("rank", option, value));

        Assert.Equal((int)ExitCode.InvalidInput, code);
    }

    [Fact]
    public void A_failing_analyzer_fails_rank_instead_of_printing_a_ranking_without_the_verdicts_that_were_asked_for()
    {
        string failing = FakeAnalyzerScript.Create(_root, exitCode: 4);
        (int code, string output, string error) = Run("rank", Project, "--advisories", Osv, "--symbols", Symbols, "--analyzer", failing);

        Assert.Equal((int)ExitCode.InternalError, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("exit code 4", error);
    }

    [Fact]
    public void Sarif_carries_the_reachability_as_a_property_when_it_was_computed()
    {
        (int code, string sarif, _) = Run(WithReach("ci", "--format", "sarif"));
        (_, string plain, _) = Run(WithoutReach("ci", "--format", "sarif"));

        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument with = JsonDocument.Parse(sarif);
        JsonElement[] results = with.RootElement.GetProperty("runs")[0].GetProperty("results").EnumerateArray().ToArray();
        JsonElement reached = results.Single(r => r.GetProperty("ruleId").GetString() == "DEPRISK-EXAMPLE-0001").GetProperty("properties");

        Assert.Equal("reachable", reached.GetProperty("reachability").GetString());
        Assert.Equal("static-path", reached.GetProperty("reachabilityReason").GetString());

        using JsonDocument without = JsonDocument.Parse(plain);
        Assert.All(
            without.RootElement.GetProperty("runs")[0].GetProperty("results").EnumerateArray(),
            r => Assert.False(r.GetProperty("properties").TryGetProperty("reachability", out _)));
    }

    [Fact]
    public void A_ci_run_with_reachability_in_an_initialized_project_is_audited_with_the_decision()
    {
        Assert.Equal((int)ExitCode.Success, Run("init", _root).Code);

        Assert.Equal((int)ExitCode.Success, Run(WithReach("ci", "--fail-on", "unreachable")).Code);
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);

        string last = File.ReadAllLines(Path.Combine(_root, ".deprisk", "audit.log")).Last();
        Assert.Contains("\"command\":\"ci\"", last);
        Assert.Contains("unreachable", last);
        Assert.Contains("passed", last);
    }
}

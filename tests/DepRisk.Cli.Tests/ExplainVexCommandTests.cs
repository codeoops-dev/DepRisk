using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>explain and vex end to end on the reach fixtures, with a stand-in analyzer.</summary>
public sealed class ExplainVexCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-explain-vex-" + Guid.NewGuid().ToString("N"));

    private string Project => Path.Combine(_root, "proj");

    private string Osv => Path.Combine(_root, "osv");

    private string Symbols => Path.Combine(_root, "symbols");

    public ExplainVexCommandTests()
    {
        Directory.CreateDirectory(Project);
        Directory.CreateDirectory(Osv);
        Directory.CreateDirectory(Symbols);
        File.WriteAllText(Path.Combine(Project, "project.assets.json"), NpmFixtures.ReadReach("assets/project.assets.json"));

        foreach (string id in new[] { "0001", "0002", "0003" })
        {
            File.WriteAllText(Path.Combine(Osv, $"DEPRISK-EXAMPLE-{id}.json"), NpmFixtures.ReadReach($"osv/DEPRISK-EXAMPLE-{id}.json"));
        }

        File.WriteAllText(Path.Combine(Symbols, "example.json"), NpmFixtures.ReadReach("symbols/example.json"));
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

    /// <summary>A map that also covers Other.Lib (a direct package) with a complete list, and an analyzer that finds no path for it.</summary>
    private string[] WithUnreachableDirectPackage()
    {
        File.WriteAllText(Path.Combine(Symbols, "other.json"), """
            { "schemaVersion": 1, "language": "csharp", "entries": [
              { "advisory": "DEPRISK-EXAMPLE-0003", "package": "Other.Lib", "symbols": ["Other.Lib.Thing.Run"], "complete": true, "source": "test: complete list" } ] }
            """);

        string canned = FakeAnalyzerScript.Canned.Replace(
            "\"results\":[",
            "\"results\":[{\"key\":\"DEPRISK-EXAMPLE-0003|Other.Lib\",\"label\":\"unreachable\",\"reason\":\"no-path\",\"symbol\":null,\"path\":[]},",
            StringComparison.Ordinal);

        return ["--symbols", Symbols, "--analyzer", FakeAnalyzerScript.Create(_root, canned)];
    }

    private string[] Reach() => ["--symbols", Symbols, "--analyzer", FakeAnalyzerScript.Create(_root)];

    // --- explain ---

    [Fact]
    public void Explain_answers_for_an_alias_with_the_evidence_the_path_and_what_would_change_it()
    {
        (int code, string output, string error) = Run(["explain", "CVE-2099-0001", Project, "--advisories", Osv, .. Reach()]);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("deprisk explain CVE-2099-0001: 1 finding(s)", output);
        Assert.Contains("Newtonsoft.Json 12.0.1: DEPRISK-EXAMPLE-0001 (also CVE-2099-0001)", output);
        Assert.Contains("Ranked first of 3, ahead of #2 (DEPRISK-EXAMPLE-0002)", output);
        Assert.Contains("fixed in 13.0.1", output);
        Assert.Contains("installed as a direct dependency", output);
        Assert.Contains("Reachability: reachable: a call path exists.", output);
        Assert.Contains("Path step 1: Sample.Program.Main -> Sample.Program.Load, static (Program.cs:9).", output);
        Assert.Contains("The symbols come from: example only", output);
        Assert.Contains("Upgrading Newtonsoft.Json to 13.0.1 or later removes this finding.", output);
        Assert.Contains("Every line is built from the data in the result", output);
    }

    [Fact]
    public void Explain_without_symbols_says_reachability_was_not_analyzed_and_how_to_get_it()
    {
        (int code, string output, _) = Run("explain", "DEPRISK-EXAMPLE-0003", Project, "--advisories", Osv);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Reachability was not analyzed (no symbol maps were given).", output);
        Assert.Contains("Add --symbols", output);
    }

    [Fact]
    public void Explain_with_the_risk_model_compares_with_the_baseline_and_labels_the_parameters()
    {
        (int code, string output, _) = Run("explain", "DEPRISK-EXAMPLE-0002", Project, "--advisories", Osv, "--model", "risk");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("by the mean of its modeled risk", output);
        Assert.Contains("The baseline method (KEV, then EPSS, then CVSS)", output);
        Assert.Contains("uncalibrated-defaults", output);
        Assert.Contains("not probabilities of real-world loss", output);
    }

    [Fact]
    public void Explain_json_is_deterministic_and_follows_the_contract()
    {
        string[] args = ["explain", "DEPRISK-EXAMPLE-0001", Project, "--advisories", Osv, .. Reach(), "--format", "json"];

        (_, string one, _) = Run(args);
        (_, string two, _) = Run(args);

        Assert.Equal(one, two);

        using JsonDocument document = JsonDocument.Parse(one);
        JsonElement finding = document.RootElement.GetProperty("findings")[0];

        Assert.Equal("DEPRISK-EXAMPLE-0001", finding.GetProperty("finding").GetProperty("id").GetString());
        Assert.Equal("reachable", finding.GetProperty("reachability").GetProperty("label").GetString());
        Assert.Equal(2, finding.GetProperty("reachability").GetProperty("path").GetArrayLength());
        Assert.Equal(1, finding.GetProperty("position").GetProperty("rank").GetInt32());
        Assert.True(finding.GetProperty("evidence").GetArrayLength() > 5);
        Assert.DoesNotContain(_root, one);
    }

    [Fact]
    public void An_unknown_advisory_or_a_missing_one_is_an_input_error()
    {
        (int missing, _, string e1) = Run("explain", "NOPE", Project, "--advisories", Osv);
        (int none, _, string e2) = Run("explain", "--advisories", Osv);
        (int package, _, string e3) = Run("explain", "DEPRISK-EXAMPLE-0001", Project, "--advisories", Osv, "--package", "Other.Lib");

        Assert.Equal((int)ExitCode.InvalidInput, missing);
        Assert.Contains("no finding for 'NOPE'", e1);
        Assert.Contains("DEPRISK-EXAMPLE-0001", e1);
        Assert.Equal((int)ExitCode.InvalidInput, none);
        Assert.Contains("needs the advisory id", e2);
        Assert.Equal((int)ExitCode.InvalidInput, package);
        Assert.Contains("in package 'Other.Lib'", e3);
    }

    [Theory]
    [InlineData("--format", "sarif")]
    [InlineData("--nope", "x")]
    [InlineData("--model", "magic")]
    [InlineData("--samples", "10")]
    [InlineData("--analyzer", "x")]
    public void Bad_options_are_input_errors_for_explain(string option, string value)
    {
        (int code, _, _) = Run("explain", "DEPRISK-EXAMPLE-0001", Project, "--advisories", Osv, option, value);

        Assert.Equal((int)ExitCode.InvalidInput, code);
    }

    // --- vex ---

    private static JsonElement[] Statements(JsonDocument document) => document.RootElement.GetProperty("statements").EnumerateArray().ToArray();

    private static string StatusOf(JsonElement[] statements, string advisory) =>
        statements.Single(s => s.GetProperty("vulnerability").GetProperty("name").GetString() == advisory).GetProperty("status").GetString()!;

    [Fact]
    public void Vex_maps_the_verdicts_to_statuses_and_never_claims_not_affected_for_a_transitive_package()
    {
        (int code, string output, string error) = Run(
            ["vex", Project, "--advisories", Osv, .. WithUnreachableDirectPackage(), "--product", "pkg:nuget/Sample@1.0.0", "--author", "Example Team", "--timestamp", "2026-11-05T12:00:00Z"]);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement[] statements = Statements(document);

        Assert.Equal("affected", StatusOf(statements, "DEPRISK-EXAMPLE-0001"));            // reachable
        Assert.Equal("under_investigation", StatusOf(statements, "DEPRISK-EXAMPLE-0002")); // the analyzer said unreachable, but the package is transitive
        Assert.Equal("not_affected", StatusOf(statements, "DEPRISK-EXAMPLE-0003"));        // unreachable, direct, complete list, every file read

        JsonElement notAffected = statements.Single(s => s.GetProperty("status").GetString() == "not_affected");
        Assert.Equal("vulnerable_code_not_in_execute_path", notAffected.GetProperty("justification").GetString());
        Assert.Contains("deprisk-reach 9.9.9", notAffected.GetProperty("impact_statement").GetString());
        Assert.Equal("pkg:nuget/Other.Lib@2.0.0", notAffected.GetProperty("products")[0].GetProperty("subcomponents")[0].GetProperty("@id").GetString());
        Assert.Equal("pkg:nuget/Sample@1.0.0", notAffected.GetProperty("products")[0].GetProperty("@id").GetString());
    }

    [Fact]
    public void Without_symbols_every_statement_is_under_investigation()
    {
        (int code, string output, _) = Run("vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0", "--author", "Example Team");

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        Assert.All(Statements(document), s => Assert.Equal("under_investigation", s.GetProperty("status").GetString()));
    }

    [Fact]
    public void Vex_with_a_pinned_timestamp_is_byte_identical_and_without_one_uses_the_current_time()
    {
        string[] pinned = ["vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0", "--author", "A", "--timestamp", "2026-11-05T12:00:00Z"];

        (_, string one, _) = Run(pinned);
        (_, string two, _) = Run(pinned);
        Assert.Equal(one, two);

        (_, string now, _) = Run("vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0", "--author", "A");
        using JsonDocument document = JsonDocument.Parse(now);
        DateTimeOffset stamp = DateTimeOffset.Parse(document.RootElement.GetProperty("timestamp").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(Math.Abs((DateTimeOffset.UtcNow - stamp).TotalMinutes) < 5);
    }

    [Fact]
    public void Vex_needs_a_product_and_an_author_and_a_valid_timestamp()
    {
        (int a, _, string e1) = Run("vex", Project, "--advisories", Osv, "--author", "A");
        (int b, _, string e2) = Run("vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0");
        (int c, _, string e3) = Run("vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0", "--author", "A", "--timestamp", "yesterday-ish");
        (int d, _, string e4) = Run("vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0", "--author", "A\u001b[31m");
        (int e, _, string e5) = Run("vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0", "--author", "A", "--format", "table");

        Assert.Equal((int)ExitCode.InvalidInput, a);
        Assert.Contains("needs --product", e1);
        Assert.Equal((int)ExitCode.InvalidInput, b);
        Assert.Contains("needs --author", e2);
        Assert.Equal((int)ExitCode.InvalidInput, c);
        Assert.Contains("RFC 3339", e3);
        Assert.Equal((int)ExitCode.InvalidInput, d);
        Assert.Contains("control characters", e4);
        Assert.Equal((int)ExitCode.InvalidInput, e);
        Assert.Contains("OpenVEX, which is JSON", e5);
    }

    [Fact]
    public void Vex_writes_a_file_and_a_run_in_an_initialized_project_is_audited()
    {
        Assert.Equal((int)ExitCode.Success, Run("init", _root).Code);

        (int code, string output, _) = Run("vex", Project, "--advisories", Osv, "--product", "pkg:nuget/Sample@1.0.0", "--author", "A", "--out", "vex.json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Wrote OpenVEX to vex.json (3 statement(s))", output);
        Assert.Equal("https://openvex.dev/ns/v0.2.0", JsonDocument.Parse(File.ReadAllText(Path.Combine(_root, "vex.json"))).RootElement.GetProperty("@context").GetString());

        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);
        Assert.Contains("\"command\":\"vex\"", File.ReadAllLines(Path.Combine(_root, ".deprisk", "audit.log")).Last());
    }

    [Fact]
    public void Help_lists_the_new_commands()
    {
        (_, string help, _) = Run("help");

        Assert.Contains("explain <id> [path]", help);
        Assert.Contains("vex [path]", help);
        Assert.Contains("--product <purl|iri>", help);
    }
}

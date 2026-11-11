using System.Text;
using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// reach, rank, explain, and vex on an npm project (tests/fixtures/reach-npm) with a stand-in for the analyzer. The real analyzer is
/// exercised by its own tests and by the reach-e2e job in CI.
/// </summary>
public sealed class ReachNpmTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-reach-npm-" + Guid.NewGuid().ToString("N"));

    /// <summary>
    /// What the real analyzer says for the fixture: example-lib is called (reachable), other-lib is imported but its symbols are not
    /// used (unreachable), deep-lib is not used at all (unreachable, but it is only transitive), and @scope/client has a symbol list
    /// that is not complete, which the analyzer reports as unknown.
    /// </summary>
    private const string Canned = """
        {"schemaVersion":1,"analyzer":{"name":"deprisk-reach","version":"9.9.9"},"language":"javascript","sourceDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
         "stats":{"files":1,"filesSkipped":0,"filesWithErrors":0,"types":0,"methods":2,"edges":3,"entrypoints":1,"reflectionSites":0},
         "entrypoints":[{"method":"src/app.js::<module>","kind":"module"}],"results":[
           {"key":"DEPRISK-NPM-0001|example-lib","label":"reachable","reason":"static-path","symbol":"example-lib::parse",
            "path":[{"from":"src/app.js::<module>","to":"src/app.js::load","kind":"static","file":"src/app.js","line":9},
                    {"from":"src/app.js::load","to":"example-lib::parse","kind":"static","file":"src/app.js","line":6}]},
           {"key":"DEPRISK-NPM-0002|other-lib","label":"unreachable","reason":"no-path","symbol":null,"path":[]},
           {"key":"DEPRISK-NPM-0003|deep-lib","label":"unreachable","reason":"no-path","symbol":null,"path":[]},
           {"key":"DEPRISK-NPM-0004|@scope/client","label":"unknown","reason":"symbol-list-incomplete","symbol":null,"path":[]}
         ],"diagnostics":[]}
        """;

    public ReachNpmTests()
    {
        Directory.CreateDirectory(_root);

        foreach (string name in new[]
        {
            "package.json",
            "package-lock.json",
            "osv/DEPRISK-NPM-0001.json",
            "osv/DEPRISK-NPM-0002.json",
            "osv/DEPRISK-NPM-0003.json",
            "osv/DEPRISK-NPM-0004.json",
            "symbols/npm-example.json",
            "src/app.js",
        })
        {
            // The lockfile is stored as package-lock.fixture.json: a file called package-lock.json in the repository would make a scan of
            // the repository root find both ecosystems.
            string target = Path.Combine(_root, name.Replace('/', Path.DirectorySeparatorChar));
            string resource = name == "package-lock.json" ? "package-lock.fixture.json" : name;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllText(target, NpmFixtures.ReadReachNpm(resource), new UTF8Encoding(false));
        }
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

    private string[] Common(string command, string json = Canned, params string[] extra) =>
        [command, _root, "--advisories", Path.Combine(_root, "osv"), "--symbols", Path.Combine(_root, "symbols"), "--analyzer", FakeAnalyzerScript.Create(_root, json), .. extra];

    private static JsonElement Finding(JsonDocument doc, string id) =>
        doc.RootElement.GetProperty("findings").EnumerateArray().Single(f => f.GetProperty("finding").GetProperty("id").GetString() == id);

    [Fact]
    public void Reach_labels_the_npm_findings_and_never_calls_a_transitive_or_incomplete_one_unreachable()
    {
        (int code, string output, string error) = Run(Common("reach", Canned, "--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument doc = JsonDocument.Parse(output);
        Assert.Equal("npm", doc.RootElement.GetProperty("ecosystem").GetString());

        JsonElement reachable = Finding(doc, "DEPRISK-NPM-0001").GetProperty("reachability");
        Assert.Equal("reachable", reachable.GetProperty("label").GetString());
        Assert.Equal("example-lib::parse", reachable.GetProperty("symbol").GetString());
        Assert.Equal("src/app.js::load", reachable.GetProperty("path")[0].GetProperty("to").GetString());

        JsonElement unreachable = Finding(doc, "DEPRISK-NPM-0002").GetProperty("reachability");
        Assert.Equal("unreachable", unreachable.GetProperty("label").GetString());

        // deep-lib is only a dependency of a dependency: the project cannot call it directly, so the analyzer's "unreachable" is not trusted.
        JsonElement transitive = Finding(doc, "DEPRISK-NPM-0003").GetProperty("reachability");
        Assert.Equal("unknown", transitive.GetProperty("label").GetString());
        Assert.Equal("transitive-package-code-not-analyzed", transitive.GetProperty("reason").GetString());

        // @scope/client has a symbol list that is not complete: the analyzer says so and nothing is claimed.
        JsonElement incomplete = Finding(doc, "DEPRISK-NPM-0004").GetProperty("reachability");
        Assert.Equal("unknown", incomplete.GetProperty("label").GetString());
        Assert.Equal("symbol-list-incomplete", incomplete.GetProperty("reason").GetString());
    }

    [Fact]
    public void The_table_for_an_npm_project_names_the_package_symbols()
    {
        (int code, string output, _) = Run(Common("reach"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("example-lib", output);
        Assert.Contains("reachable", output);
        Assert.Contains("example-lib::parse", output);
    }

    [Fact]
    public void Rank_and_explain_use_the_npm_reachability()
    {
        (int code, string output, _) = Run(Common("rank", Canned, "--model", "risk", "--format", "json"));
        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument ranked = JsonDocument.Parse(output);
        JsonElement first = ranked.RootElement.GetProperty("findings").EnumerateArray().Single(f => f.GetProperty("id").GetString() == "DEPRISK-NPM-0001");
        Assert.Equal("reachable", first.GetProperty("reachability").GetProperty("label").GetString());

        string[] explain =
        [
            "explain", "DEPRISK-NPM-0001", _root, "--advisories", Path.Combine(_root, "osv"), "--symbols", Path.Combine(_root, "symbols"),
            "--analyzer", FakeAnalyzerScript.Create(_root, Canned),
        ];
        (int explainCode, string explained, string explainError) = Run(explain);
        Assert.Equal((int)ExitCode.Success, explainCode);
        Assert.Equal(string.Empty, explainError);
        Assert.Contains("DEPRISK-NPM-0001", explained);
    }

    [Fact]
    public void Vex_says_not_affected_only_for_the_direct_unreachable_finding_with_a_complete_symbol_list()
    {
        (int code, string output, string error) = Run(Common("vex", Canned, "--product", "pkg:npm/demo-app@1.0.0", "--author", "tests", "--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument doc = JsonDocument.Parse(output);
        Dictionary<string, string> status = doc.RootElement.GetProperty("statements").EnumerateArray().ToDictionary(
            s => s.GetProperty("vulnerability").GetProperty("name").GetString()!,
            s => s.GetProperty("status").GetString()!);

        Assert.Equal("not_affected", status["DEPRISK-NPM-0002"]);
        Assert.Equal("affected", status["DEPRISK-NPM-0001"]);
        Assert.Equal("under_investigation", status["DEPRISK-NPM-0003"]);
        Assert.Equal("under_investigation", status["DEPRISK-NPM-0004"]);
    }

    [Fact]
    public void A_symbol_map_for_the_other_language_does_not_apply_and_says_so()
    {
        File.Delete(Path.Combine(_root, "symbols", "npm-example.json"));
        File.WriteAllText(
            Path.Combine(_root, "symbols", "csharp.json"),
            """{ "schemaVersion": 1, "language": "csharp", "entries": [ { "advisory": "DEPRISK-NPM-0001", "package": "example-lib", "symbols": [ "Example.Lib.Parser.Parse" ], "complete": true, "source": "test" } ] }""");

        (int code, string output, _) = Run(Common("reach", Canned, "--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument doc = JsonDocument.Parse(output);
        Assert.All(doc.RootElement.GetProperty("findings").EnumerateArray(), f => Assert.Equal("unknown", f.GetProperty("reachability").GetProperty("label").GetString()));
        Assert.Contains(doc.RootElement.GetProperty("diagnostics").EnumerateArray(), d => d.GetString()!.Contains("no entries for JavaScript and TypeScript (npm)", StringComparison.Ordinal));
    }

    [Fact]
    public void An_analyzer_that_answers_for_the_wrong_language_is_a_protocol_error_not_a_verdict()
    {
        string csharpAnswer = Canned.Replace("\"language\":\"javascript\"", "\"language\":\"csharp\"", StringComparison.Ordinal);

        (int code, string output, string error) = Run(Common("reach", csharpAnswer, "--format", "json"));

        Assert.Equal((int)ExitCode.InternalError, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("not the JavaScript and TypeScript reachability analyzer", error);
    }

    [Fact]
    public void Explicit_entry_points_are_function_ids_for_npm_and_method_names_for_nuget()
    {
        (int ok, _, string okError) = Run(Common("reach", Canned, "--entrypoint", "src/app.js::load", "--entrypoint", "src/app.js::*"));
        Assert.Equal((int)ExitCode.Success, ok);
        Assert.Equal(string.Empty, okError);

        (int bad, _, string badError) = Run(Common("reach", Canned, "--entrypoint", "Sample.Program.Main"));
        Assert.Equal((int)ExitCode.InvalidInput, bad);
        Assert.Contains("is not a function id for JavaScript or TypeScript", badError);

        (int nonsense, _, string nonsenseError) = Run(Common("reach", Canned, "--entrypoint", "not an id"));
        Assert.Equal((int)ExitCode.InvalidInput, nonsense);
        Assert.Contains("is not an entry point name", nonsenseError);
    }

    [Fact]
    public void A_javascript_symbol_map_applied_to_a_nuget_project_does_not_apply_and_says_so()
    {
        string nuget = Path.Combine(_root, "nuget");
        foreach (string name in new[] { "assets/project.assets.json", "osv/DEPRISK-EXAMPLE-0001.json", "osv/DEPRISK-EXAMPLE-0002.json", "osv/DEPRISK-EXAMPLE-0003.json" })
        {
            string target = Path.Combine(nuget, name.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllText(target, NpmFixtures.ReadReach(name));
        }

        (int code, string output, _) = Run(
            "reach", Path.Combine(nuget, "assets"), "--advisories", Path.Combine(nuget, "osv"), "--symbols", Path.Combine(_root, "symbols"),
            "--analyzer", FakeAnalyzerScript.Create(_root), "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument doc = JsonDocument.Parse(output);
        Assert.All(doc.RootElement.GetProperty("findings").EnumerateArray(), f => Assert.Equal("unknown", f.GetProperty("reachability").GetProperty("label").GetString()));
        Assert.Contains(doc.RootElement.GetProperty("diagnostics").EnumerateArray(), d => d.GetString()!.Contains("no entries for C# (NuGet)", StringComparison.Ordinal));
    }
}

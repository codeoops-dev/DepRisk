using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// The reach command end to end, with a stand-in analyzer: a small script that ignores the request and prints a canned result.
/// (The real analyzer is exercised by its own tests and by the reach-e2e job in CI.)
/// </summary>
public sealed class ReachCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-reach-cli-" + Guid.NewGuid().ToString("N"));

    private string Project => Path.Combine(_root, "proj");

    private string Osv => Path.Combine(_root, "osv");

    private string Symbols => Path.Combine(_root, "symbols", "example.json");

    public ReachCommandTests()
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

    private const string CannedResult = """
        {"schemaVersion":1,"analyzer":{"name":"deprisk-reach","version":"9.9.9"},"language":"csharp","sourceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "stats":{"files":3,"filesSkipped":0,"filesWithErrors":0,"types":2,"methods":5,"edges":4,"entrypoints":1,"reflectionSites":0},
         "entrypoints":[],"results":[
           {"key":"DEPRISK-EXAMPLE-0001|Newtonsoft.Json","label":"reachable","reason":"static-path","symbol":"Newtonsoft.Json.JsonConvert.DeserializeObject",
            "path":[{"from":"Sample.Program.Main","to":"Sample.Program.Load","kind":"static","file":"Program.cs","line":9},
                    {"from":"Sample.Program.Load","to":"Newtonsoft.Json.JsonConvert.DeserializeObject","kind":"static","file":"Program.cs","line":14}]},
           {"key":"DEPRISK-EXAMPLE-0002|Example.Lib","label":"unreachable","reason":"no-path","symbol":null,"path":[]}
         ],"diagnostics":[]}
        """;

    /// <summary>An executable that prints <paramref name="json"/>, whatever it is given.</summary>
    private string FakeAnalyzer(string json = CannedResult, int exitCode = 0)
    {
        string canned = Path.Combine(_root, "canned.json");
        File.WriteAllText(canned, json);

        if (OperatingSystem.IsWindows())
        {
            string cmd = Path.Combine(_root, "fake-analyzer.cmd");
            File.WriteAllText(cmd, $"@echo off\r\ntype \"{canned}\"\r\nexit /b {exitCode}\r\n");
            return cmd;
        }

        string script = Path.Combine(_root, "fake-analyzer.sh");
        File.WriteAllText(script, $"#!/bin/sh\ncat \"{canned}\"\nexit {exitCode}\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return script;
    }

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private string[] Standard(params string[] extra) =>
        ["reach", Project, "--advisories", Osv, "--symbols", Symbols, "--analyzer", FakeAnalyzer(), .. extra];

    [Fact]
    public void The_table_says_what_is_reachable_why_and_how()
    {
        (int code, string output, string error) = Run(Standard());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("deprisk reach: 3 finding(s), ecosystem NuGet", output);
        Assert.Contains("analyzer: deprisk-reach 9.9.9", output);
        Assert.Contains("summary: 1 reachable, 0 possibly reachable, 2 unknown, 0 unreachable", output);
        Assert.Contains("reachable          DEPRISK-EXAMPLE-0001  Newtonsoft.Json 12.0.1 (direct)", output);
        Assert.Contains("via Newtonsoft.Json.JsonConvert.DeserializeObject", output);
        Assert.Contains("Sample.Program.Main -> Sample.Program.Load -> Newtonsoft.Json.JsonConvert.DeserializeObject  (Program.cs:14)", output);
        Assert.Contains("symbols from: example only", output);
        Assert.Contains("transitive dependency: its own code is not analyzed", output);
        Assert.Contains("no symbol list for this advisory (add one with --symbols)", output);
        Assert.Contains("not exploitability", output);

        // Most urgent first.
        Assert.True(output.IndexOf("EXAMPLE-0001", StringComparison.Ordinal) < output.IndexOf("EXAMPLE-0002", StringComparison.Ordinal));
    }

    [Fact]
    public void The_json_is_the_documented_contract()
    {
        (int code, string output, _) = Run(Standard("--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;

        Assert.Equal("nuget", root.GetProperty("ecosystem").GetString());
        Assert.Equal(1, root.GetProperty("summary").GetProperty("reachable").GetInt32());
        Assert.Equal("example.json", root.GetProperty("symbolMaps").GetProperty("source").GetString());
        Assert.Equal(64, root.GetProperty("analyzer").GetProperty("sha256").GetString()!.Length);
        Assert.Equal("reachable", root.GetProperty("findings")[0].GetProperty("reachability").GetProperty("label").GetString());
        Assert.Equal(2, root.GetProperty("findings")[0].GetProperty("reachability").GetProperty("path").GetArrayLength());
        Assert.DoesNotContain(_root, output);
    }

    [Fact]
    public void Out_writes_a_file_and_prints_a_summary()
    {
        (int code, string output, _) = Run(Standard("--format", "json", "--out", "reach.json"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Wrote json reachability to reach.json (1 reachable, 0 possibly reachable, 0 unreachable, 2 unknown)", output);
        Assert.True(JsonDocument.Parse(File.ReadAllText(Path.Combine(_root, "reach.json"))).RootElement.TryGetProperty("findings", out _));
    }

    [Fact]
    public void Missing_inputs_are_input_errors_that_say_what_to_pass()
    {
        (int noAdvisories, _, string e1) = Run("reach", Project, "--symbols", Symbols);
        (int noSymbols, _, string e2) = Run("reach", Project, "--advisories", Osv);

        Assert.Equal((int)ExitCode.InvalidInput, noAdvisories);
        Assert.Contains("needs advisory data", e1);
        Assert.Equal((int)ExitCode.InvalidInput, noSymbols);
        Assert.Contains("needs symbol maps", e2);
        Assert.Contains("OSV has no symbol data for NuGet", e2);
    }

    [Theory]
    [InlineData("--timeout", "0")]
    [InlineData("--timeout", "99999")]
    [InlineData("--timeout", "soon")]
    [InlineData("--entrypoints", "everything")]
    [InlineData("--entrypoint", "Run")]
    [InlineData("--entrypoint", "A.B.#ctor")]
    [InlineData("--entrypoint", "A.B C")]
    [InlineData("--format", "sarif")]
    [InlineData("--ecosystem", "pypi")]
    [InlineData("--nope", "x")]
    public void Bad_option_values_are_input_errors(string option, string value)
    {
        (int code, _, string error) = Run(Standard(option, value));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.NotEqual(string.Empty, error);
    }

    [Fact]
    public void A_good_explicit_entrypoint_and_the_equals_form_are_accepted()
    {
        (int code, _, _) = Run(Standard("--entrypoint=App.Worker.Run", "--entrypoint", "App.Worker.*", "--entrypoints=none", "--timeout=30"));

        Assert.Equal((int)ExitCode.Success, code);
    }

    [Fact]
    public void A_missing_analyzer_is_an_input_error_with_instructions()
    {
        (int code, _, string error) = Run("reach", Project, "--advisories", Osv, "--symbols", Symbols, "--analyzer", Path.Combine(_root, "nope"));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("--analyzer does not exist", error);
    }

    [Fact]
    public void A_failing_analyzer_is_an_internal_error()
    {
        (int code, _, string error) = Run("reach", Project, "--advisories", Osv, "--symbols", Symbols, "--analyzer", FakeAnalyzer(exitCode: 3));

        Assert.Equal((int)ExitCode.InternalError, code);
        Assert.Contains("exit code 3", error);
    }

    [Fact]
    public void A_result_that_breaks_the_protocol_is_an_internal_error_and_nothing_is_printed_as_a_verdict()
    {
        (int code, string output, string error) = Run("reach", Project, "--advisories", Osv, "--symbols", Symbols, "--analyzer", FakeAnalyzer("{ this is not the protocol"));

        Assert.Equal((int)ExitCode.InternalError, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("analyzer", error);
    }

    [Fact]
    public void A_broken_symbol_map_is_an_input_error_naming_the_file_and_entry()
    {
        File.WriteAllText(Symbols, """{ "schemaVersion": 1, "language": "csharp", "entries": [ { "advisory": "A", "package": "P", "symbols": ["A.B.C"], "source": "t" } ] }""");

        (int code, _, string error) = Run(Standard());

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("example.json: entry 0", error);
        Assert.Contains("complete", error);
    }

    [Fact]
    public void Help_and_doctor_know_about_the_command_and_the_analyzer()
    {
        (_, string help, _) = Run("help");
        (_, string doctor, _) = Run("doctor");

        Assert.Contains("reach [path]", help);
        Assert.Contains("--symbols <file|dir>", help);
        Assert.Contains("deprisk-reach", doctor);
    }

    [Fact]
    public void A_run_in_an_initialized_project_is_audited_and_the_log_verifies()
    {
        Assert.Equal((int)ExitCode.Success, Run("init", _root).Code);

        Assert.Equal((int)ExitCode.Success, Run(Standard("--format", "json", "--out", "reach.json")).Code);
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);

        string[] lines = File.ReadAllLines(Path.Combine(_root, ".deprisk", "audit.log"));
        Assert.Equal(2, lines.Length);
        Assert.Contains("\"command\":\"reach\"", lines[1]);
    }
}

using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class GraphCommandTests : IDisposable
{
    private const string Assets = """
    {
      "version": 3,
      "targets": {
        "net10.0": {
          "Lib.A/1.0.0": { "type": "package", "dependencies": { "Lib.B": "[1.0.0, 1.2.0)", "Lib.Missing": "1.0.0", "Lib.Weird": "1.*", "Lib.C": "2.0.0" } },
          "Lib.B/1.5.0": { "type": "package", "dependencies": { "Lib.C": "2.0.0" } },
          "Lib.C/2.1.0": { "type": "package" },
          "Lib.Weird/1.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net10.0": ["Lib.A >= 1.0.0"] },
      "project": { "restore": { "projectName": "Sample", "projectPath": "/elsewhere/Sample.csproj" } }
    }
    """;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-graph-" + Guid.NewGuid().ToString("N"));

    public GraphCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src", "Sample", "obj"));
        File.WriteAllText(Path.Combine(_root, "src", "Sample", "obj", "project.assets.json"), Assets);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string LogPath => Path.Combine(_root, ".deprisk", "audit.log");

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public void The_table_summarizes_the_hypergraph_and_lists_violated_and_undecided_requirements()
    {
        (int code, string output, string error) = Run("graph", _root);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("Sample  (src/Sample/Sample.csproj)", output);
        Assert.Contains("4 node(s) (1 direct), 3 hyperedge(s) (max arity 5)", output);
        Assert.Contains("1 violated, 2 undecided, 1 shared", output);
        Assert.Contains("VIOLATED  Lib.A@1.0.0 requires Lib.B [1.0.0, 1.2.0) but the project resolved 1.5.0", output);
        Assert.Contains("undecided Lib.Missing 1.0.0 (not in the resolved graph)", output);
        Assert.Contains("undecided Lib.Weird 1.* (range not understood)", output);
    }

    [Fact]
    public void Json_output_has_nodes_hyperedges_requirements_and_stats()
    {
        (int code, string output, _) = Run("graph", _root, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("nuget", root.GetProperty("ecosystem").GetString());

        JsonElement target = root.GetProperty("projects")[0].GetProperty("targets")[0];
        Assert.Equal("net10.0", target.GetProperty("name").GetString());
        Assert.Equal(4, target.GetProperty("nodes").GetArrayLength());
        Assert.Equal(">= 1.0.0", target.GetProperty("nodes").EnumerateArray().Single(n => n.GetProperty("id").GetString() == "Lib.A").GetProperty("requested").GetString());

        JsonElement[] edges = target.GetProperty("hyperedges").EnumerateArray().ToArray();
        Assert.Equal(new[] { "project:Sample", "Lib.A@1.0.0", "Lib.B@1.5.0" }, edges.Select(e => e.GetProperty("id").GetString()).ToArray());

        JsonElement a = edges[1];
        Assert.Equal("package", a.GetProperty("kind").GetString());
        Assert.Equal(5, a.GetProperty("arity").GetInt32());
        Assert.False(a.GetProperty("satisfied").GetBoolean());

        JsonElement violated = a.GetProperty("requires").EnumerateArray().Single(r => r.GetProperty("package").GetString() == "Lib.B");
        Assert.Equal("[1.0.0, 1.2.0)", violated.GetProperty("range").GetString());
        Assert.Equal("1.5.0", violated.GetProperty("resolved").GetString());
        Assert.False(violated.GetProperty("satisfied").GetBoolean());

        JsonElement missing = a.GetProperty("requires").EnumerateArray().Single(r => r.GetProperty("package").GetString() == "Lib.Missing");
        Assert.Equal(JsonValueKind.Null, missing.GetProperty("resolved").ValueKind);
        Assert.Equal(JsonValueKind.Null, missing.GetProperty("satisfied").ValueKind);

        JsonElement stats = target.GetProperty("stats");
        Assert.Equal(1, stats.GetProperty("violated").GetInt32());
        Assert.Equal(2, stats.GetProperty("unresolved").GetInt32());
        Assert.Equal(5, stats.GetProperty("maxArity").GetInt32());
    }

    [Fact]
    public void Dot_output_is_a_digraph_with_the_violation_in_red()
    {
        (int code, string output, _) = Run("graph", _root, "--format", "dot");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.StartsWith("digraph deprisk {", output);
        Assert.Contains("color=red", output);
        Assert.Contains("c0:Lib.A@1.0.0", output);
    }

    [Fact]
    public void Out_writes_the_file_and_reports_it()
    {
        string target = Path.Combine(_root, "graph.dot");

        (int code, string output, _) = Run("graph", _root, "--format", "dot", "--out", target);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Wrote dot hypergraph", output);
        Assert.StartsWith("digraph deprisk {", File.ReadAllText(target));
    }

    [Fact]
    public void Output_is_identical_between_runs()
    {
        (_, string first, _) = Run("graph", _root, "--format", "json");
        (_, string second, _) = Run("graph", _root, "--format", "json");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Input_errors_are_exit_code_4()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run("graph", Path.Combine(_root, "missing")).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("graph", _root, "--format", "sarif").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("graph", _root, "--nope").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("graph", _root, _root).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("graph", _root, "--format").Code);

        string empty = Path.Combine(_root, "empty");
        Directory.CreateDirectory(empty);
        (int code, _, string error) = Run("graph", empty);
        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("dotnet restore", error);
    }

    [Fact]
    public void In_an_initialized_project_graph_is_audited_and_the_digests_track_the_input()
    {
        Run("init");

        Run("graph", _root, "--format", "json");
        File.WriteAllText(
            Path.Combine(_root, "src", "Sample", "obj", "project.assets.json"),
            Assets.Replace("Lib.B/1.5.0", "Lib.B/1.1.0", StringComparison.Ordinal));
        Run("graph", _root, "--format", "json");

        string[] lines = File.ReadAllLines(LogPath);
        Assert.Equal(3, lines.Length);

        using JsonDocument first = JsonDocument.Parse(lines[1]);
        using JsonDocument second = JsonDocument.Parse(lines[2]);
        Assert.Equal("graph", first.RootElement.GetProperty("command").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("inputsDigest").GetString(),
            second.RootElement.GetProperty("inputsDigest").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("outputsDigest").GetString(),
            second.RootElement.GetProperty("outputsDigest").GetString());
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify").Code);
    }

    [Fact]
    public void Scan_json_now_shows_the_requested_constraint_of_direct_dependencies()
    {
        (_, string output, _) = Run("scan", _root, "--format", "json");

        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement packages = document.RootElement.GetProperty("projects")[0].GetProperty("targets")[0].GetProperty("packages");
        JsonElement a = packages.EnumerateArray().Single(p => p.GetProperty("id").GetString() == "Lib.A");
        JsonElement b = packages.EnumerateArray().Single(p => p.GetProperty("id").GetString() == "Lib.B");

        Assert.Equal(">= 1.0.0", a.GetProperty("requested").GetString());
        Assert.Equal(JsonValueKind.Null, b.GetProperty("requested").ValueKind);
    }
}

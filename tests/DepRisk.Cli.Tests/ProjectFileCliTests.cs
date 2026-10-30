using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class ProjectFileCliTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-pf-" + Guid.NewGuid().ToString("N"));

    public ProjectFileCliTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src", "Sample", "obj"));
        File.WriteAllText(
            Path.Combine(_root, "src", "Sample", "obj", "project.assets.json"),
            """
            { "version": 3, "targets": { "net10.0": { "Pkg/1.0.0": { "type": "package" } } },
              "projectFileDependencyGroups": { "net10.0": ["Pkg >= 1.0.0"] },
              "project": { "restore": { "projectName": "Sample", "projectPath": "C:\\Users\\Someone\\code\\src\\Sample\\Sample.csproj" } } }
            """);
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public void Scan_json_has_the_project_file_relative_to_the_scanned_directory_and_no_machine_path()
    {
        (int code, string output, _) = Run("scan", _root, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        Assert.Equal("src/Sample/Sample.csproj", document.RootElement.GetProperty("projects")[0].GetProperty("projectFile").GetString());
        Assert.False(output.Contains("Someone", StringComparison.Ordinal), "the machine-specific path must not leak");
    }

    [Fact]
    public void Scanning_the_assets_file_directly_cannot_tell_the_project_file()
    {
        string file = Path.Combine(_root, "src", "Sample", "obj", "project.assets.json");

        (_, string output, _) = Run("scan", file, "--format", "json");

        using JsonDocument document = JsonDocument.Parse(output);
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("projects")[0].GetProperty("projectFile").ValueKind);
    }
}

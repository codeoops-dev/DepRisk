using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class ScanCommandTests : IDisposable
{
    private const string SampleAssets = """
    {
      "version": 3,
      "targets": {
        "net10.0": {
          "Pkg.One/1.0.0": { "type": "package", "dependencies": { "Pkg.Two": "2.0.0" } },
          "Pkg.Two/2.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net10.0": ["Pkg.One >= 1.0.0"] },
      "project": { "restore": { "projectName": "Sample" } }
    }
    """;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-tests-" + Guid.NewGuid().ToString("N"));

    public ScanCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src", "Sample", "obj"));
        File.WriteAllText(Path.Combine(_root, "src", "Sample", "obj", "project.assets.json"), SampleAssets);
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

    [Fact]
    public void Json_output_has_schema_version_and_the_resolved_packages()
    {
        (int code, string output, string error) = Run("scan", _root, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("nuget", root.GetProperty("ecosystem").GetString());

        JsonElement project = root.GetProperty("projects")[0];
        Assert.Equal("Sample", project.GetProperty("name").GetString());
        Assert.Equal("src/Sample/obj/project.assets.json", project.GetProperty("assetsFile").GetString());

        JsonElement packages = project.GetProperty("targets")[0].GetProperty("packages");
        Assert.Equal(2, packages.GetArrayLength());
        Assert.Equal("Pkg.One", packages[0].GetProperty("id").GetString());
        Assert.True(packages[0].GetProperty("isDirect").GetBoolean());
        Assert.False(packages[1].GetProperty("isDirect").GetBoolean());
    }

    [Fact]
    public void Json_output_is_identical_between_runs()
    {
        (_, string first, _) = Run("scan", _root, "--format=json");
        (_, string second, _) = Run("scan", _root, "--format=json");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Table_output_lists_direct_and_transitive_packages()
    {
        (int code, string output, _) = Run("scan", _root);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Sample", output);
        Assert.Contains("1 direct, 1 transitive", output);
        Assert.Contains("Pkg.One", output);
        Assert.Contains("transitive", output);
    }

    [Fact]
    public void A_path_to_the_assets_file_itself_works()
    {
        string file = Path.Combine(_root, "src", "Sample", "obj", "project.assets.json");

        (int code, string output, _) = Run("scan", file, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("\"assetsFile\": \"project.assets.json\"", output);
    }

    [Fact]
    public void Out_option_writes_the_file_and_prints_a_confirmation()
    {
        string target = Path.Combine(_root, "scan.json");

        (int code, string output, _) = Run("scan", _root, "--format", "json", "--out", target);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Wrote json scan result", output);
        Assert.Contains("\"schemaVersion\": 1", File.ReadAllText(target));
    }

    [Fact]
    public void Directory_without_assets_files_is_an_input_error_with_a_hint()
    {
        string empty = Path.Combine(_root, "empty");
        Directory.CreateDirectory(empty);

        (int code, string output, string error) = Run("scan", empty);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("dotnet restore", error);
    }

    [Fact]
    public void Missing_path_is_an_input_error()
    {
        (int code, _, string error) = Run("scan", Path.Combine(_root, "does-not-exist"));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("path not found", error);
    }

    [Fact]
    public void Broken_assets_file_is_an_input_error_naming_the_file()
    {
        string broken = Path.Combine(_root, "broken");
        Directory.CreateDirectory(Path.Combine(broken, "obj"));
        File.WriteAllText(Path.Combine(broken, "obj", "project.assets.json"), "{ nope");

        (int code, _, string error) = Run("scan", broken);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("obj/project.assets.json", error);
    }

    [Theory]
    [InlineData("--nope")]
    [InlineData("--format=sarif")]
    [InlineData("--format=xml")]
    public void Unknown_options_and_unsupported_formats_are_input_errors(string option)
    {
        (int code, _, string error) = Run("scan", _root, option);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.NotEqual(string.Empty, error);
    }

    [Fact]
    public void Option_without_value_is_an_input_error()
    {
        (int code, _, string error) = Run("scan", _root, "--format");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("needs a value", error);
    }

    [Fact]
    public void More_than_one_path_is_an_input_error()
    {
        (int code, _, _) = Run("scan", _root, _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
    }
}

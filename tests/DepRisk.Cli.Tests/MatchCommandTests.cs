using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class MatchCommandTests : IDisposable
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

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-match-" + Guid.NewGuid().ToString("N"));

    public MatchCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "Sample", "obj"));
        File.WriteAllText(Path.Combine(_root, "Sample", "obj", "project.assets.json"), SampleAssets);
        Directory.CreateDirectory(AdvisoryDir);
        WriteAdvisory("GHSA-high.json", Advisory("GHSA-high", "Pkg.Two", "0", "2.1.0", "HIGH", "Pkg.Two is vulnerable"));
        WriteAdvisory("GHSA-fixed.json", Advisory("GHSA-fixed", "Pkg.One", "0", "1.0.0", "CRITICAL", "already fixed in 1.0.0"));
        WriteAdvisory("GHSA-withdrawn.json", """{ "id": "GHSA-w", "withdrawn": "2026-01-01T00:00:00Z" }""");
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string AdvisoryDir => Path.Combine(_root, "osv");

    private string LogPath => Path.Combine(_root, ".deprisk", "audit.log");

    private static string Advisory(string id, string package, string introduced, string fixedIn, string severity, string summary) => $$"""
        {
          "id": "{{id}}",
          "summary": {{JsonSerializer.Serialize(summary)}},
          "database_specific": { "severity": "{{severity}}" },
          "affected": [ { "package": { "ecosystem": "NuGet", "name": "{{package}}" },
            "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "{{introduced}}" }, { "fixed": "{{fixedIn}}" } ] } ] } ]
        }
        """;

    private void WriteAdvisory(string name, string content) => File.WriteAllText(Path.Combine(AdvisoryDir, name), content);

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public void Json_output_lists_only_the_vulnerable_version_with_fix_and_location()
    {
        (int code, string output, string error) = Run("match", _root, "--advisories", AdvisoryDir, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("osv", root.GetProperty("advisories").GetProperty("source").GetString());
        Assert.Equal(2, root.GetProperty("advisories").GetProperty("count").GetInt32());
        Assert.Equal(1, root.GetProperty("advisories").GetProperty("skippedWithdrawn").GetInt32());
        Assert.Equal(1, root.GetProperty("projectsScanned").GetInt32());
        Assert.Equal(2, root.GetProperty("packagesScanned").GetInt32());

        JsonElement finding = Assert.Single(root.GetProperty("findings").EnumerateArray().ToArray());
        Assert.Equal("GHSA-high", finding.GetProperty("id").GetString());
        Assert.Equal("Pkg.Two", finding.GetProperty("package").GetProperty("id").GetString());
        Assert.Equal("2.0.0", finding.GetProperty("package").GetProperty("version").GetString());
        Assert.Equal("HIGH", finding.GetProperty("severity").GetString());
        Assert.Equal("2.1.0", finding.GetProperty("fixedVersions")[0].GetString());
        Assert.False(finding.GetProperty("locations")[0].GetProperty("isDirect").GetBoolean());
    }

    [Fact]
    public void Table_output_is_readable_and_states_its_limits()
    {
        (int code, string output, _) = Run("match", _root, "-a", AdvisoryDir);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("1 project(s), 2 package version(s) scanned", output);
        Assert.Contains("findings: 1", output);
        Assert.Contains("HIGH", output);
        Assert.Contains("GHSA-high", output);
        Assert.Contains("Pkg.Two 2.0.0 (transitive)", output);
        Assert.Contains("fixed in 2.1.0", output);
        Assert.Contains("reachability", output);
    }

    [Fact]
    public void No_findings_says_so_and_warns_about_completeness()
    {
        File.Delete(Path.Combine(AdvisoryDir, "GHSA-high.json"));

        (int code, string output, _) = Run("match", _root, "--advisories", AdvisoryDir);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("No known vulnerabilities found", output);
        Assert.Contains("only as complete as the advisory data", output);
    }

    [Fact]
    public void A_zip_of_advisories_works_too()
    {
        string zip = Path.Combine(_root, "NuGet.zip");
        System.IO.Compression.ZipFile.CreateFromDirectory(AdvisoryDir, zip);

        (int code, string output, _) = Run("match", _root, "--advisories", zip, "--format=json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("\"source\": \"NuGet.zip\"", output);
        Assert.Contains("GHSA-high", output);
    }

    [Fact]
    public void Advisory_data_is_required_and_the_message_says_how_to_get_it()
    {
        (int code, string output, string error) = Run("match", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("--advisories", error);
        Assert.Contains("osv-vulnerabilities", error);
    }

    [Fact]
    public void Input_errors_are_exit_code_4()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run("match", _root, "--advisories", Path.Combine(_root, "missing")).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("match", _root, "--advisories", AdvisoryDir, "--format", "sarif").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("match", _root, "--advisories", AdvisoryDir, "--nope").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("match", _root, _root, "--advisories", AdvisoryDir).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("match", _root, "--advisories").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("match", Path.Combine(_root, "empty-project"), "--advisories", AdvisoryDir).Code);
    }

    [Fact]
    public void Invalid_advisory_records_are_reported_loudly_and_strict_turns_them_into_an_error()
    {
        WriteAdvisory("broken.json", "{ not json");

        (int code, string output, _) = Run("match", _root, "--advisories", AdvisoryDir);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("WARNING: 1 advisory record(s) could not be read", output);
        Assert.Contains("broken.json", output);

        (int strictCode, string strictOutput, string strictError) = Run("match", _root, "--advisories", AdvisoryDir, "--strict");

        Assert.Equal((int)ExitCode.InvalidInput, strictCode);
        Assert.Equal(string.Empty, strictOutput);
        Assert.Contains("--strict", strictError);
    }

    [Fact]
    public void Terminal_control_sequences_in_advisory_text_never_reach_the_terminal()
    {
        WriteAdvisory(
            "GHSA-evil.json",
            Advisory("GHSA-evil", "Pkg.Two", "0", "9.0.0", "HIGH", "\u001b[2J\u001b[31mHACKED\u001b[0m\u0007 bell"));

        (_, string table, _) = Run("match", _root, "--advisories", AdvisoryDir);
        (_, string json, _) = Run("match", _root, "--advisories", AdvisoryDir, "--format", "json");

        // Ordinal checks on purpose: xunit 2's string overloads compare culture-sensitively, and under ICU
        // control characters such as ESC and BEL are "ignorable", so they would "match" any string.
        Assert.False(table.Contains('\u001b'), "table output must not contain ESC");
        Assert.False(table.Contains('\u0007'), "table output must not contain BEL");
        Assert.Contains("HACKED", table);
        Assert.False(json.Contains('\u001b'), "JSON output must not contain a raw ESC");
        Assert.Contains("\\u001B", json);
    }

    [Fact]
    public void Output_is_identical_between_runs()
    {
        (_, string first, _) = Run("match", _root, "--advisories", AdvisoryDir, "--format", "json");
        (_, string second, _) = Run("match", _root, "--advisories", AdvisoryDir, "--format", "json");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Out_writes_the_file_and_reports_the_finding_count()
    {
        string target = Path.Combine(_root, "findings.json");

        (int code, string output, _) = Run("match", _root, "--advisories", AdvisoryDir, "--format", "json", "--out", target);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("1 finding(s)", output);
        Assert.Contains("\"findings\"", File.ReadAllText(target));
    }

    [Fact]
    public void In_an_initialized_project_match_is_audited_and_the_digests_track_the_data()
    {
        Run("init");

        Run("match", _root, "--advisories", AdvisoryDir, "--format", "json");
        WriteAdvisory("GHSA-high.json", Advisory("GHSA-high", "Pkg.Two", "0", "2.2.0", "HIGH", "changed data"));
        Run("match", _root, "--advisories", AdvisoryDir, "--format", "json");

        string[] lines = File.ReadAllLines(LogPath);
        Assert.Equal(3, lines.Length);

        using JsonDocument first = JsonDocument.Parse(lines[1]);
        using JsonDocument second = JsonDocument.Parse(lines[2]);
        Assert.Equal("match", first.RootElement.GetProperty("command").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("inputsDigest").GetString(),
            second.RootElement.GetProperty("inputsDigest").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("outputsDigest").GetString(),
            second.RootElement.GetProperty("outputsDigest").GetString());

        Assert.Equal((int)ExitCode.Success, Run("audit", "verify").Code);
    }

    [Fact]
    public void Match_without_init_writes_no_audit_data()
    {
        Run("match", _root, "--advisories", AdvisoryDir);

        Assert.False(Directory.Exists(Path.Combine(_root, ".deprisk")));
    }
}

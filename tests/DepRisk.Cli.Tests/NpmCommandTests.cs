using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class NpmCommandTests : IDisposable
{
    private const string Critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-npm-cli-" + Guid.NewGuid().ToString("N"));

    public NpmCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "web"));
        File.WriteAllText(Path.Combine(_root, "web", "package.json"), "{}");
        File.WriteAllText(Path.Combine(_root, "web", "package-lock.json"), NpmFixtures.Read(NpmFixtures.Simple));

        Directory.CreateDirectory(AdvisoryDir);

        // ms 2.0.0 (nested, transitive): critical, fixed in 2.1.3. debug 2.6.9 (direct): medium, no fix.
        File.WriteAllText(Path.Combine(AdvisoryDir, "ms.json"), Advisory("GHSA-ms", "CVE-2099-0101", "ms", Critical, "CRITICAL", "2.1.3"));
        File.WriteAllText(Path.Combine(AdvisoryDir, "debug.json"), Advisory("GHSA-debug", "CVE-2099-0102", "debug", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "MODERATE", null));
        File.WriteAllText(Path.Combine(_root, "kev.json"), """{ "catalogVersion": "k1", "vulnerabilities": [ { "cveID": "CVE-2099-0102", "dateAdded": "2026-01-01" } ] }""");
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string AdvisoryDir => Path.Combine(_root, "osv");

    private static string Advisory(string id, string cve, string package, string vector, string severity, string? fixedIn) =>
        $$"""
        {
          "id": "{{id}}", "aliases": ["{{cve}}"], "summary": "Synthetic advisory for {{package}}",
          "severity": [ { "type": "CVSS_V3", "score": "{{vector}}" } ],
          "database_specific": { "severity": "{{severity}}" },
          "affected": [ { "package": { "ecosystem": "npm", "name": "{{package}}" },
            "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }{{(fixedIn is null ? string.Empty : $", {{ \"fixed\": \"{fixedIn}\" }}")}} ] } ] } ]
        }
        """;

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public void Scan_detects_npm_and_prints_the_installed_packages()
    {
        (int code, string output, string error) = Run("scan", _root);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("ecosystem npm", output);
        Assert.Contains("sample-web  (web/package-lock.json)", output);
        Assert.Contains("npm: 26 package(s) (6 direct, 20 transitive)", output);
    }

    [Fact]
    public void Scan_json_for_npm_has_paths_and_project_file()
    {
        (int code, string output, _) = Run("scan", _root, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement project = document.RootElement.GetProperty("projects")[0];

        Assert.Equal("npm", document.RootElement.GetProperty("ecosystem").GetString());
        Assert.Equal("web/package.json", project.GetProperty("projectFile").GetString());
        Assert.Contains(
            project.GetProperty("targets")[0].GetProperty("packages").EnumerateArray(),
            p => p.GetProperty("path").GetString() == "node_modules/debug/node_modules/ms");
    }

    [Fact]
    public void Match_reports_the_vulnerable_npm_packages()
    {
        (int code, string output, _) = Run("match", _root, "--advisories", AdvisoryDir);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("2 npm advisories", output);
        Assert.Contains("findings: 2", output);
        Assert.Contains("GHSA-ms  ms 2.0.0 (transitive); fixed in 2.1.3", output);
        Assert.Contains("GHSA-debug  debug 2.6.9 (direct); no fixed version known", output);
    }

    [Fact]
    public void Match_json_uses_the_renamed_counter()
    {
        (int code, string output, _) = Run("match", _root, "--advisories", AdvisoryDir, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement advisories = document.RootElement.GetProperty("advisories");

        Assert.Equal("npm", document.RootElement.GetProperty("ecosystem").GetString());
        Assert.Equal(0, advisories.GetProperty("skippedOtherEcosystem").GetInt32());
        Assert.False(advisories.TryGetProperty("skippedNotNuGet", out _));
    }

    [Fact]
    public void Rank_orders_kev_first_for_npm()
    {
        (int code, string output, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--kev", Path.Combine(_root, "kev.json"), "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement findings = document.RootElement.GetProperty("findings");

        Assert.Equal("npm", document.RootElement.GetProperty("ecosystem").GetString());
        Assert.Equal("GHSA-debug", findings[0].GetProperty("id").GetString());   // in KEV, although only medium
        Assert.Equal("GHSA-ms", findings[1].GetProperty("id").GetString());
    }

    [Fact]
    public void Ci_gates_npm_findings_and_writes_sarif_against_package_json()
    {
        (int failCode, _, string failError) = Run("ci", _root, "--advisories", AdvisoryDir, "--fail-on", "cvss>=9&fixable");
        (int passCode, _, _) = Run("ci", _root, "--advisories", AdvisoryDir, "--fail-on", "ransomware");

        Assert.Equal((int)ExitCode.PolicyGateFailed, failCode);
        Assert.Contains("GHSA-ms", failError);
        Assert.Equal((int)ExitCode.Success, passCode);

        (int sarifCode, string sarif, _) = Run("ci", _root, "--advisories", AdvisoryDir, "--format", "sarif");

        Assert.Equal((int)ExitCode.Success, sarifCode);
        using JsonDocument document = JsonDocument.Parse(sarif);
        JsonElement result = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
        string uri = result.GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString()!;

        Assert.Equal("web/package.json", uri);
    }

    [Fact]
    public void A_tree_with_both_ecosystems_asks_for_a_choice_and_the_choice_works()
    {
        Directory.CreateDirectory(Path.Combine(_root, "App", "obj"));
        File.WriteAllText(
            Path.Combine(_root, "App", "obj", "project.assets.json"),
            """{ "version": 3, "targets": { "net10.0": { "P/1.0.0": { "type": "package" } } }, "projectFileDependencyGroups": { "net10.0": ["P >= 1.0.0"] } }""");

        (int code, _, string error) = Run("scan", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("--ecosystem nuget or --ecosystem npm", error);

        (int npmCode, string npm, _) = Run("scan", _root, "--ecosystem", "npm");
        (int nugetCode, string nuget, _) = Run("scan", _root, "--ecosystem=nuget");

        Assert.Equal((int)ExitCode.Success, npmCode);
        Assert.Contains("ecosystem npm", npm);
        Assert.Equal((int)ExitCode.Success, nugetCode);
        Assert.Contains("ecosystem nuget", nuget);
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("graph")]
    [InlineData("match")]
    [InlineData("rank")]
    [InlineData("ci")]
    public void An_unknown_ecosystem_is_an_input_error_for_every_command(string command)
    {
        (int code, _, string error) = Run(command, _root, "--ecosystem", "pypi", "--advisories", AdvisoryDir);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("ecosystem 'pypi' is not supported", error);
    }

    [Fact]
    public void Graph_says_plainly_that_it_is_not_available_for_npm_yet()
    {
        (int code, string output, string error) = Run("graph", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("supports NuGet projects only", error);
        Assert.Contains("npm", error);
    }

    [Fact]
    public void An_npm_run_in_an_initialized_project_is_audited_and_the_log_verifies()
    {
        Assert.Equal((int)ExitCode.Success, Run("init", _root).Code);

        Assert.Equal((int)ExitCode.Success, Run("rank", _root, "--advisories", AdvisoryDir, "--ecosystem", "npm", "--format", "json", "--out", "ranking.json").Code);
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);

        string[] lines = File.ReadAllLines(Path.Combine(_root, ".deprisk", "audit.log"));
        Assert.Equal(2, lines.Length);
        Assert.Contains("--ecosystem", lines[1]);
        Assert.Contains("\"command\":\"rank\"", lines[1]);
    }

    [Fact]
    public void A_broken_lock_file_is_an_input_error_naming_the_file()
    {
        File.WriteAllText(Path.Combine(_root, "web", "package-lock.json"), """{ "lockfileVersion": 1, "dependencies": {} }""");

        (int code, _, string error) = Run("scan", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("web/package-lock.json", error);
        Assert.Contains("lockfileVersion 1", error);
    }

    [Fact]
    public void Help_mentions_the_ecosystem_option()
    {
        (int code, string output, _) = Run("help");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("--ecosystem auto|nuget|npm", output);
        Assert.Contains("package-lock.json", output);
    }
}

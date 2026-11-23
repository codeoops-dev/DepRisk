using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>NuGet packages.lock.json and npm lockfileVersion 1 through the commands (ADR 0027).</summary>
public sealed class LockfileCommandTests : IDisposable
{
    private const string Critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-lockfile-cli-" + Guid.NewGuid().ToString("N"));

    public LockfileCommandTests() => Directory.CreateDirectory(Path.Combine(_root, "osv"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private void Put(string relative, string content)
    {
        string path = Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private static string Advisory(string id, string ecosystem, string package, string fixedIn, string range) =>
        $$"""
        {
          "id": "{{id}}", "aliases": [], "summary": "Synthetic advisory for {{package}}",
          "severity": [ { "type": "CVSS_V3", "score": "{{Critical}}" } ],
          "database_specific": { "severity": "CRITICAL" },
          "affected": [ { "package": { "ecosystem": "{{ecosystem}}", "name": "{{package}}" },
            "ranges": [ { "type": "{{range}}", "events": [ { "introduced": "0" }, { "fixed": "{{fixedIn}}" } ] } ] } ]
        }
        """;

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private const string NuGetLock = """
        { "version": 1, "dependencies": { "net10.0": {
            "Demo.Logging": { "type": "Direct", "requested": "[3.0.0, )", "resolved": "3.0.0", "contentHash": "x", "dependencies": { "Demo.Core": "1.0.0" } },
            "Demo.Core": { "type": "Transitive", "resolved": "1.0.0", "contentHash": "y" },
            "shared": { "type": "Project", "dependencies": { "Demo.Core": "1.0.0" } } } } }
        """;

    [Fact]
    public void Scan_prints_the_packages_of_a_nuget_lock_file_that_has_no_assets_file()
    {
        Put("App/packages.lock.json", NuGetLock);
        Put("App/App.csproj", "<Project />");

        (int code, string output, _) = Run("scan", _root);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Demo.Logging", output);
        Assert.Contains("Demo.Core", output);
        Assert.DoesNotContain("shared", output);
    }

    [Fact]
    public void Match_finds_a_vulnerable_package_in_a_nuget_lock_file()
    {
        Put("App/packages.lock.json", NuGetLock);
        Put("osv/core.json", Advisory("GHSA-core", "NuGet", "Demo.Core", "1.0.1", "ECOSYSTEM"));

        (int code, string output, _) = Run("match", _root, "--advisories", Path.Combine(_root, "osv"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("findings: 1", output);
        Assert.Contains("GHSA-core  Demo.Core 1.0.0 (transitive); fixed in 1.0.1", output);
    }

    [Fact]
    public void Match_finds_a_vulnerable_package_in_an_npm_lockfile_version_1_and_knows_what_is_direct()
    {
        Put("web/package.json", """{ "dependencies": { "ms": "2.0.0", "from-git": "github:a/b" } }""");
        Put("web/package-lock.json", """
            { "lockfileVersion": 1, "requires": true, "dependencies": {
                "ms": { "version": "2.0.0" },
                "from-git": { "version": "github:a/b#abc" } } }
            """);
        Put("osv/ms.json", Advisory("GHSA-ms", "npm", "ms", "2.1.3", "SEMVER"));

        (int code, string output, _) = Run("match", _root, "--advisories", Path.Combine(_root, "osv"), "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        Assert.Equal("npm", document.RootElement.GetProperty("ecosystem").GetString());
        Assert.Equal(1, document.RootElement.GetProperty("packagesSkipped").GetInt32());   // the git dependency: no version to match
        JsonElement finding = Assert.Single(document.RootElement.GetProperty("findings").EnumerateArray().ToArray());
        Assert.Equal("ms", finding.GetProperty("package").GetProperty("id").GetString());
        Assert.True(finding.GetProperty("locations")[0].GetProperty("isDirect").GetBoolean());
    }

    [Fact]
    public void A_version_1_lock_file_without_a_package_json_is_an_input_error_that_says_what_to_do()
    {
        Put("web/package-lock.json", """{ "lockfileVersion": 1, "dependencies": {} }""");

        (int code, _, string error) = Run("scan", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("web/package-lock.json", error);
        Assert.Contains("web/package.json", error);
    }
}

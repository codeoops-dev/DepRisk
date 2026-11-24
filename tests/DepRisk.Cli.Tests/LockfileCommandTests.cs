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

    [Fact]
    public void Rank_scores_an_advisory_that_has_only_a_cvss_v4_vector()
    {
        Put("App/packages.lock.json", NuGetLock);
        Put("osv/core.json", """
            { "id": "GHSA-v4", "aliases": [], "summary": "v4 only",
              "severity": [ { "type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" } ],
              "affected": [ { "package": { "ecosystem": "NuGet", "name": "Demo.Core" },
                "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "1.0.1" } ] } ] } ] }
            """);

        (int code, string output, _) = Run("rank", _root, "--advisories", Path.Combine(_root, "osv"), "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement cvss = document.RootElement.GetProperty("findings")[0].GetProperty("signals").GetProperty("cvss");
        Assert.Equal("4.0", cvss.GetProperty("version").GetString());
        Assert.Equal(9.3, cvss.GetProperty("baseScore").GetDouble());
        Assert.Equal("CRITICAL", cvss.GetProperty("rating").GetString());

        (int tableCode, string table, _) = Run("rank", _root, "--advisories", Path.Combine(_root, "osv"));
        Assert.Equal((int)ExitCode.Success, tableCode);
        Assert.Contains("CVSS 9.3 CRITICAL", table);
    }

    [Fact]
    public void A_credential_in_a_url_range_reaches_no_output_of_any_command()
    {
        const string secret = "TOKEN123";
        Put("web/package.json", $$"""{ "dependencies": { "a": "git+https://user:{{secret}}@example.com/org/a.git" } }""");
        Put("web/package-lock.json", $$"""
            { "name": "demo", "lockfileVersion": 3, "packages": {
                "": { "name": "demo", "dependencies": { "a": "git+https://user:{{secret}}@example.com/org/a.git" } },
                "node_modules/a": { "version": "1.0.0", "dependencies": { "b": "git+https://user:{{secret}}@example.com/org/b.git#semver:^1" } },
                "node_modules/b": { "version": "1.2.0" } } }
            """);
        Put("osv/b.json", Advisory("GHSA-b", "npm", "b", "1.3.0", "SEMVER"));
        string advisories = Path.Combine(_root, "osv");

        string[][] commands =
        [
            ["scan", _root, "--format", "json"],
            ["scan", _root],
            ["graph", _root, "--format", "json"],
            ["match", _root, "--advisories", advisories, "--format", "json"],
            ["rank", _root, "--advisories", advisories, "--format", "json"],
            ["rank", _root, "--advisories", advisories, "--format", "sarif"],
            ["rank", _root, "--advisories", advisories],
        ];

        foreach (string[] command in commands)
        {
            (int code, string output, string error) = Run(command);

            Assert.True(code == (int)ExitCode.Success, $"{string.Join(' ', command[..1])} exited {code}: {error}");
            Assert.DoesNotContain(secret, output);
            Assert.DoesNotContain(secret, error);
        }

        (_, string json, _) = Run("scan", _root, "--format", "json");
        Assert.Contains("git+https://***@example.com/org/a.git", json);
    }

    private const string NpmSbom = """
        { "bomFormat": "CycloneDX", "specVersion": "1.5",
          "metadata": { "component": { "bom-ref": "root", "name": "demo", "purl": "pkg:npm/demo@1.0.0" } },
          "components": [
            { "bom-ref": "debug", "name": "debug", "version": "2.6.9", "purl": "pkg:npm/debug@2.6.9" },
            { "bom-ref": "ms", "name": "ms", "version": "2.0.0", "purl": "pkg:npm/ms@2.0.0?download_url=https%3A%2F%2Fu%3ATOKEN123%40h%2Fms.tgz" } ],
          "dependencies": [ { "ref": "root", "dependsOn": [ "debug" ] }, { "ref": "debug", "dependsOn": [ "ms" ] }, { "ref": "ms", "dependsOn": [] } ] }
        """;

    [Fact]
    public void Scan_match_and_rank_start_from_an_sbom_and_know_what_is_transitive()
    {
        Put("sbom/app.cdx.json", NpmSbom);
        Put("osv/ms.json", Advisory("GHSA-ms", "npm", "ms", "2.1.3", "SEMVER"));
        string file = Path.Combine(_root, "sbom", "app.cdx.json");
        string advisories = Path.Combine(_root, "osv");

        (int scanCode, string scan, _) = Run("scan", file);
        Assert.Equal((int)ExitCode.Success, scanCode);
        Assert.Contains("debug", scan);
        Assert.Contains("1 direct, 1 transitive", scan);

        (int matchCode, string match, _) = Run("match", file, "--advisories", advisories);
        Assert.Equal((int)ExitCode.Success, matchCode);
        Assert.Contains("GHSA-ms  ms 2.0.0 (transitive); fixed in 2.1.3", match);

        foreach (string format in new[] { "json", "sarif" })
        {
            (int code, string output, string error) = Run("rank", file, "--advisories", advisories, "--format", format);
            Assert.Equal((int)ExitCode.Success, code);
            Assert.DoesNotContain("TOKEN123", output);
            Assert.DoesNotContain("TOKEN123", error);
        }
    }

    [Fact]
    public void Graph_refuses_an_sbom_and_a_directory_scan_does_not_find_one()
    {
        Put("sbom/bom.json", NpmSbom);

        (int graphCode, _, string graphError) = Run("graph", Path.Combine(_root, "sbom", "bom.json"));
        Assert.Equal((int)ExitCode.InvalidInput, graphCode);
        Assert.Contains("an SBOM records neither", graphError);

        (int scanCode, _, string scanError) = Run("scan", Path.Combine(_root, "sbom"));
        Assert.Equal((int)ExitCode.InvalidInput, scanCode);
        Assert.Contains("SBOM is read only when its path is given", scanError);
    }

    [Fact]
    public void A_flat_sbom_is_an_input_error_that_says_what_to_do()
    {
        Put("sbom/flat.cdx.json", """
            { "bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": { "component": { "bom-ref": "root", "name": "demo" } },
              "components": [ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0" } ] }
            """);

        (int code, _, string error) = Run("scan", Path.Combine(_root, "sbom", "flat.cdx.json"));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("flat.cdx.json", error);
        Assert.Contains("records no dependency relationships", error);
    }
}

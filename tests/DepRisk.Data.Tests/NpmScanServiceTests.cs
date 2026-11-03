using DepRisk.Core;
using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Data.Npm;
using DepRisk.Data.NuGet;
using DepRisk.Data.Osv;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class NpmScanServiceTests : IDisposable
{
    private static readonly ToolInfo Tool = new("deprisk", "0.0.0-test");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-npm-scan-" + Guid.NewGuid().ToString("N"));

    public NpmScanServiceTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Put(string relative, string content)
    {
        string path = Path.Combine(_root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private const string NuGetAssets = """{ "version": 3, "targets": { "net10.0": { "P/1.0.0": { "type": "package" } } }, "projectFileDependencyGroups": { "net10.0": ["P >= 1.0.0"] } }""";

    [Fact]
    public void A_directory_with_only_a_lock_file_is_read_as_npm()
    {
        Put("web/package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));
        Put("web/package.json", "{}");

        ScanResult result = ScanService.Scan(_root, Tool);

        Assert.Equal("npm", result.Ecosystem);
        ProjectGraph project = Assert.Single(result.Projects);
        Assert.Equal("web/package-lock.json", project.AssetsFile);
        Assert.Equal("web/package.json", project.ProjectFile);
    }

    [Fact]
    public void The_project_file_is_null_when_package_json_is_missing()
    {
        Put("package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));

        Assert.Null(Assert.Single(ScanService.Scan(_root, Tool).Projects).ProjectFile);
    }

    [Fact]
    public void A_directory_with_only_an_assets_file_is_still_read_as_nuget()
    {
        Put("App/obj/project.assets.json", NuGetAssets);

        Assert.Equal("nuget", ScanService.Scan(_root, Tool).Ecosystem);
    }

    [Fact]
    public void Both_kinds_of_files_is_an_error_that_asks_for_a_choice()
    {
        Put("App/obj/project.assets.json", NuGetAssets);
        Put("web/package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool));

        Assert.Contains("--ecosystem", error.Message);
        Assert.Contains("NuGet (1 project.assets.json)", error.Message);
        Assert.Contains("npm (1 package-lock.json)", error.Message);

        Assert.Equal("npm", ScanService.Scan(_root, Tool, Ecosystem.Npm).Ecosystem);
        Assert.Equal("nuget", ScanService.Scan(_root, Tool, Ecosystem.NuGet).Ecosystem);
    }

    [Fact]
    public void Nothing_found_names_both_files_and_both_commands()
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool));

        Assert.Contains("project.assets.json", error.Message);
        Assert.Contains("package-lock.json", error.Message);
        Assert.Contains("dotnet restore", error.Message);
        Assert.Contains("npm install", error.Message);
    }

    [Fact]
    public void Naming_the_ecosystem_gives_that_ecosystems_hint()
    {
        Assert.Contains("npm install", Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool, Ecosystem.Npm)).Message);
        Assert.Contains("dotnet restore", Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool, Ecosystem.NuGet)).Message);
    }

    [Fact]
    public void A_file_is_recognized_by_name_and_other_names_need_an_explicit_ecosystem()
    {
        string lockFile = Put("package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));
        string renamed = Put("fixture.json", NpmFixtures.Read(NpmFixtures.Simple));

        Assert.Equal("npm", ScanService.Scan(lockFile, Tool).Ecosystem);
        Assert.Contains("--ecosystem", Assert.Throws<InvalidInputException>(() => ScanService.Scan(renamed, Tool)).Message);
        Assert.Equal("npm", ScanService.Scan(renamed, Tool, Ecosystem.Npm).Ecosystem);
    }

    [Fact]
    public void A_path_that_does_not_exist_is_reported()
    {
        Assert.Contains("path not found", Assert.Throws<InvalidInputException>(() => ScanService.Scan(Path.Combine(_root, "nope"), Tool)).Message);
    }

    [Fact]
    public void Lock_files_inside_node_modules_are_not_read()
    {
        Put("package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));
        Put("node_modules/dep/package-lock.json", NpmFixtures.Read(NpmFixtures.Workspaces));

        Assert.Single(NpmLockFileLocator.Find(_root));
        Assert.Single(ScanService.Scan(_root, Tool).Projects);
    }

    [Fact]
    public void Several_lock_files_are_all_read_in_a_fixed_order_and_the_inputs_digest_is_stable()
    {
        Put("b/package-lock.json", NpmFixtures.Read(NpmFixtures.Workspaces));
        Put("a/package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));

        ScanOutcome first = ScanService.ScanDetailed(_root, Tool);
        ScanOutcome second = ScanService.ScanDetailed(_root, Tool);

        Assert.Equal(new[] { "a/package-lock.json", "b/package-lock.json" }, first.Result.Projects.Select(p => p.AssetsFile).ToArray());
        Assert.Equal(first.InputsDigest, second.InputsDigest);
        Assert.Equal(64, first.InputsDigest.Length);
    }

    [Fact]
    public void The_scan_json_has_the_path_property_and_is_deterministic()
    {
        Put("package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));

        string one = ScanResultJson.Serialize(ScanService.Scan(_root, Tool));
        string two = ScanResultJson.Serialize(ScanService.Scan(_root, Tool));

        Assert.Equal(one, two);
        Assert.Contains("\"ecosystem\": \"npm\"", one);
        Assert.Contains("\"path\": \"node_modules/debug/node_modules/ms\"", one);
        Assert.False(one.Contains(_root, StringComparison.Ordinal));
    }

    // --- matching ---

    private static Advisory Advisory(string id, string package, string introduced, string? fixedIn)
    {
        List<RangeEvent> events = [new RangeEvent("introduced", introduced)];

        if (fixedIn is not null)
        {
            events.Add(new RangeEvent("fixed", fixedIn));
        }

        return new Advisory(id, [], $"summary {id}", false, [], "HIGH", [new AffectedPackage("npm", package, [new AffectedRange("SEMVER", events)], [])]);
    }

    private static AdvisorySnapshot Snapshot(params Advisory[] advisories) =>
        new(advisories, "test-data", new string('d', 64), 0, 4, 0, []);

    private ScanResult ScanSimple()
    {
        Put("package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));
        return ScanService.Scan(_root, Tool);
    }

    [Fact]
    public void A_nested_copy_at_an_old_version_is_found_and_the_fixed_top_level_copy_is_not()
    {
        FindingsResult result = FindingsService.Compute(ScanSimple(), Snapshot(Advisory("T-1", "ms", "0", "2.1.3")), Tool);

        Assert.Equal("npm", result.Ecosystem);
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("ms", finding.Package.Id);
        Assert.Equal("2.0.0", finding.Package.Version);
        Assert.Equal(new[] { "2.1.3" }, finding.FixedVersions.ToArray());
        Assert.False(Assert.Single(finding.Locations).IsDirect);
        Assert.Equal("sample-web", finding.Locations[0].Project);
        Assert.Equal("npm", finding.Locations[0].Target);
    }

    [Fact]
    public void An_alias_install_is_matched_by_its_real_package_name_only()
    {
        ScanResult scan = ScanSimple();

        Finding real = Assert.Single(FindingsService.Compute(scan, Snapshot(Advisory("T-2", "strip-ansi", "0", "7.0.0")), Tool).Findings);
        Assert.Equal("strip-ansi", real.Package.Id);
        Assert.True(real.Locations[0].IsDirect);

        Assert.Empty(FindingsService.Compute(scan, Snapshot(Advisory("T-3", "strip-ansi-cjs", "0", "7.0.0")), Tool).Findings);
    }

    [Fact]
    public void Scoped_names_match_ignoring_case_and_prerelease_boundaries_hold()
    {
        ScanResult scan = ScanSimple();

        Assert.Single(FindingsService.Compute(scan, Snapshot(Advisory("T-4", "@BABEL/code-frame", "7.0.0", "8.0.0")), Tool).Findings);
        Assert.Empty(FindingsService.Compute(scan, Snapshot(Advisory("T-5", "@babel/code-frame", "7.30.0-rc.1", "8.0.0")), Tool).Findings);
    }

    [Fact]
    public void The_same_package_version_at_several_paths_is_one_finding_with_one_location()
    {
        string json = """
        { "lockfileVersion": 3, "packages": {
          "": { "dependencies": { "a": "1", "b": "1", "x": "1.0.0" } },
          "node_modules/a": { "version": "1.0.0" },
          "node_modules/b": { "version": "1.0.0" },
          "node_modules/x": { "version": "1.0.0" },
          "node_modules/a/node_modules/x": { "version": "1.0.0" },
          "node_modules/b/node_modules/x": { "version": "1.0.0" } } }
        """;
        Put("package-lock.json", json);

        FindingsResult result = FindingsService.Compute(ScanService.Scan(_root, Tool), Snapshot(Advisory("T-6", "x", "0", "2.0.0")), Tool);

        Finding finding = Assert.Single(result.Findings);
        FindingLocation location = Assert.Single(finding.Locations);
        Assert.True(location.IsDirect);   // one of the copies is the project's own
        Assert.Equal(3, result.PackagesScanned);   // a, b, x: three distinct id and version pairs
    }

    [Fact]
    public void A_package_whose_version_is_not_semver_is_counted_as_skipped_never_matched()
    {
        Put("package-lock.json", """{ "lockfileVersion": 3, "packages": { "": { }, "node_modules/odd": { "version": "1.0" } } }""");

        FindingsResult result = FindingsService.Compute(ScanService.Scan(_root, Tool), Snapshot(Advisory("T-7", "odd", "0", null)), Tool);

        Assert.Empty(result.Findings);
        Assert.Equal(1, result.PackagesSkipped);
    }

    [Fact]
    public void Match_reads_advisories_for_the_ecosystem_that_was_found()
    {
        Put("package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));
        string osv = Path.Combine(_root, "osv");
        Directory.CreateDirectory(osv);
        File.WriteAllText(Path.Combine(osv, "t.json"), """
            { "id": "T-8", "affected": [ { "package": { "ecosystem": "npm", "name": "ms" }, "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "2.1.3" } ] } ] },
                                         { "package": { "ecosystem": "NuGet", "name": "ms" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" } ] } ] } ] }
            """);

        FindingsOutcome outcome = FindingsService.Match(Path.Combine(_root, "package-lock.json"), osv, Tool, strict: true);

        Assert.Equal("npm", outcome.Result.Ecosystem);
        Assert.Equal("2.0.0", Assert.Single(outcome.Result.Findings).Package.Version);
        Assert.Equal(1, outcome.Result.Advisories.Count);
    }
}

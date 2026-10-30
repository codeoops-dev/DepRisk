using System.Text.Json;
using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Data.NuGet;
using DepRisk.Data.Osv;
using Xunit;

namespace DepRisk.Data.Tests;

public class FindingsServiceTests
{
    private static readonly ToolInfo Tool = new("deprisk", "0.0.0-test");

    private static ScanResult Scan(params ProjectGraph[] projects) => new(1, Tool, "nuget", projects);

    private static ProjectGraph Project(string name, string target, params (string Id, string Version, bool Direct)[] packages) =>
        new(
            name,
            $"{name}/obj/project.assets.json",
            [new TargetGraph(target, packages.Select(p => new ResolvedPackage(p.Id, p.Version, p.Direct, [])).ToList())]);

    private static AdvisorySnapshot Snapshot(params Advisory[] advisories) =>
        new(advisories, "test-data", new string('c', 64), 2, 3, 1, ["bad.json: x"]);

    private static Advisory Advisory(string id, string package, string introduced, string? fixedIn, string? severity = "HIGH")
    {
        List<RangeEvent> events = [new RangeEvent("introduced", introduced)];

        if (fixedIn is not null)
        {
            events.Add(new RangeEvent("fixed", fixedIn));
        }

        return new Advisory(
            id,
            [],
            $"summary of {id}",
            false,
            [],
            severity,
            [new AffectedPackage("NuGet", package, [new AffectedRange("ECOSYSTEM", events)], [])]);
    }

    [Fact]
    public void A_vulnerable_package_version_produces_a_finding_with_its_fix_and_location()
    {
        ScanResult scan = Scan(Project("App", "net10.0", ("Demo.Lib.B", "1.5.0", false), ("Demo.Lib.A", "1.2.0", true)));
        AdvisorySnapshot snapshot = Snapshot(Advisory("ADV-1", "demo.lib.b", "0", "2.0.0"));

        FindingsResult result = FindingsService.Compute(scan, snapshot, Tool);

        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("ADV-1", finding.Id);
        Assert.Equal("Demo.Lib.B", finding.Package.Id);
        Assert.Equal("1.5.0", finding.Package.Version);
        Assert.Equal("HIGH", finding.Severity);
        Assert.Equal(new[] { "2.0.0" }, finding.FixedVersions.ToArray());

        FindingLocation location = Assert.Single(finding.Locations);
        // No project file is known for this graph, so the location falls back to the assets file path.
        Assert.Equal(new FindingLocation("App", "net10.0", false, "App/obj/project.assets.json"), location);
        Assert.Equal(2, result.PackagesScanned);
        Assert.Equal(1, result.ProjectsScanned);
        Assert.Equal(1, result.Advisories.SkippedInvalid);
        Assert.Equal("test-data", result.Advisories.Source);
        Assert.Equal(1, result.SchemaVersion);
    }

    [Fact]
    public void A_fixed_or_newer_version_has_no_finding()
    {
        ScanResult scan = Scan(Project("App", "net10.0", ("Pkg", "2.0.0", true)));

        FindingsResult result = FindingsService.Compute(scan, Snapshot(Advisory("ADV-1", "Pkg", "0", "2.0.0")), Tool);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void The_same_package_in_several_projects_and_targets_is_one_finding_with_all_locations()
    {
        ScanResult scan = Scan(
            Project("Web", "net10.0", ("Pkg", "1.0.0", true)),
            new ProjectGraph(
                "Api",
                "Api/obj/project.assets.json",
                [
                    new TargetGraph("net10.0", [new ResolvedPackage("Pkg", "1.0.0", false, [])]),
                    new TargetGraph("net10.0/linux-x64", [new ResolvedPackage("Pkg", "1.0.0.0", false, [])]),
                ]));

        FindingsResult result = FindingsService.Compute(scan, Snapshot(Advisory("ADV-1", "Pkg", "0", "2.0.0")), Tool);

        Finding finding = Assert.Single(result.Findings);
        Assert.Equal(
            new[] { "Api|net10.0|False", "Api|net10.0/linux-x64|False", "Web|net10.0|True" },
            finding.Locations.Select(l => $"{l.Project}|{l.Target}|{l.IsDirect}").ToArray());
        Assert.Equal(1, result.PackagesScanned);
    }

    [Fact]
    public void Different_versions_of_the_same_package_are_separate_findings()
    {
        ScanResult scan = Scan(
            Project("A", "net10.0", ("Pkg", "1.0.0", true)),
            Project("B", "net10.0", ("Pkg", "1.5.0", true)));

        FindingsResult result = FindingsService.Compute(scan, Snapshot(Advisory("ADV-1", "Pkg", "0", "2.0.0")), Tool);

        Assert.Equal(new[] { "1.0.0", "1.5.0" }, result.Findings.Select(f => f.Package.Version).ToArray());
        Assert.Equal(2, result.PackagesScanned);
    }

    [Fact]
    public void Findings_are_sorted_by_advisory_then_package_regardless_of_input_order()
    {
        ScanResult scan = Scan(Project("App", "net10.0", ("Zed", "1.0.0", true), ("Alpha", "1.0.0", true)));
        AdvisorySnapshot snapshot = Snapshot(
            Advisory("B-2", "Zed", "0", "9.0.0"),
            Advisory("A-1", "Zed", "0", "9.0.0"),
            Advisory("A-1", "Alpha", "0", "9.0.0"));

        FindingsResult result = FindingsService.Compute(scan, snapshot, Tool);

        Assert.Equal(
            new[] { "A-1|Alpha", "A-1|Zed", "B-2|Zed" },
            result.Findings.Select(f => $"{f.Id}|{f.Package.Id}").ToArray());
    }

    [Fact]
    public void Packages_with_unparsable_versions_are_counted_not_dropped_silently()
    {
        ScanResult scan = Scan(Project("App", "net10.0", ("Weird", "not-a-version", true), ("Fine", "1.0.0", true)));

        FindingsResult result = FindingsService.Compute(scan, Snapshot(), Tool);

        Assert.Equal(1, result.PackagesSkipped);
        Assert.Equal(1, result.PackagesScanned);
    }

    [Fact]
    public void The_result_serializes_to_the_documented_json_shape()
    {
        ScanResult scan = Scan(Project("App", "net10.0", ("Pkg", "1.0.0", true)));
        FindingsResult result = FindingsService.Compute(scan, Snapshot(Advisory("ADV-1", "Pkg", "0", "2.0.0")), Tool);

        string json = FindingsResultJson.Serialize(result);

        Assert.DoesNotContain("\r", json);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("nuget", root.GetProperty("ecosystem").GetString());
        Assert.Equal(64, root.GetProperty("advisories").GetProperty("digest").GetString()!.Length);
        Assert.Equal(1, root.GetProperty("projectsScanned").GetInt32());

        JsonElement finding = root.GetProperty("findings")[0];
        Assert.Equal("ADV-1", finding.GetProperty("id").GetString());
        Assert.Equal("Pkg", finding.GetProperty("package").GetProperty("id").GetString());
        Assert.Equal("2.0.0", finding.GetProperty("fixedVersions")[0].GetString());
        Assert.True(finding.GetProperty("locations")[0].GetProperty("isDirect").GetBoolean());
    }

    [Fact]
    public void Identical_input_gives_identical_bytes()
    {
        ScanResult scan = Scan(Project("App", "net10.0", ("Pkg", "1.0.0", true)));
        AdvisorySnapshot snapshot = Snapshot(Advisory("ADV-1", "Pkg", "0", "2.0.0"));

        Assert.Equal(
            FindingsResultJson.Serialize(FindingsService.Compute(scan, snapshot, Tool)),
            FindingsResultJson.Serialize(FindingsService.Compute(scan, snapshot, Tool)));
    }

    [Fact]
    public void The_real_restore_fixture_can_be_matched()
    {
        ProjectGraph graph = NuGetAssetsParser.Parse(Fixtures.SimpleApp, "obj/project.assets.json", "x");
        ScanResult scan = Scan(graph);

        // Demo.Lib.B is 1.5.0 in the fixture (a transitive dependency of Demo.Lib.A).
        FindingsResult result = FindingsService.Compute(scan, Snapshot(Advisory("ADV-B", "Demo.Lib.B", "1.0.0", "1.6.0")), Tool);

        Finding finding = Assert.Single(result.Findings);
        Assert.False(finding.Locations[0].IsDirect);
        Assert.Equal(new[] { "1.6.0" }, finding.FixedVersions.ToArray());
    }
}

using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.NuGet;
using Xunit;

namespace DepRisk.Data.Tests;

public class NuGetAssetsParserTests
{
    private static ProjectGraph ParseFixture() =>
        NuGetAssetsParser.Parse(Fixtures.SimpleApp, "obj/project.assets.json", "fallback");

    [Fact]
    public void Reads_project_name_and_single_target()
    {
        ProjectGraph graph = ParseFixture();

        Assert.Equal("App", graph.Name);
        Assert.Equal("obj/project.assets.json", graph.AssetsFile);

        TargetGraph target = Assert.Single(graph.Targets);
        Assert.Equal("net10.0", target.Name);
    }

    [Fact]
    public void Lists_all_resolved_packages_in_stable_order()
    {
        TargetGraph target = Assert.Single(ParseFixture().Targets);

        Assert.Equal(
            new[] { "Demo.Lib.A", "Demo.Lib.B", "Demo.Lib.C", "Demo.Lib.D" },
            target.Packages.Select(p => p.Id).ToArray());
    }

    [Fact]
    public void Separates_direct_from_transitive_packages()
    {
        TargetGraph target = Assert.Single(ParseFixture().Targets);

        Assert.Equal(
            new[] { "Demo.Lib.A", "Demo.Lib.D" },
            target.Packages.Where(p => p.IsDirect).Select(p => p.Id).ToArray());

        Assert.Equal(
            new[] { "Demo.Lib.B", "Demo.Lib.C" },
            target.Packages.Where(p => !p.IsDirect).Select(p => p.Id).ToArray());
    }

    [Fact]
    public void Keeps_resolved_versions_and_declared_ranges()
    {
        TargetGraph target = Assert.Single(ParseFixture().Targets);

        ResolvedPackage a = target.Packages.Single(p => p.Id == "Demo.Lib.A");
        Assert.Equal("1.2.0", a.Version);
        Assert.Equal(new[] { "Demo.Lib.B", "Demo.Lib.C" }, a.Dependencies.Select(d => d.Id).ToArray());
        Assert.Equal("[1.0.0, 2.0.0)", a.Dependencies[0].Range);
        Assert.Equal("2.1.0", a.Dependencies[1].Range);

        // The graph is resolved: C is 2.1.0 even though B only asks for >= 2.0.0.
        Assert.Equal("2.1.0", target.Packages.Single(p => p.Id == "Demo.Lib.C").Version);
    }

    [Fact]
    public void Uses_fallback_name_when_the_file_has_none()
    {
        ProjectGraph graph = NuGetAssetsParser.Parse("""{"version":3}""", "x.json", "fallback");

        Assert.Equal("fallback", graph.Name);
        Assert.Empty(graph.Targets);
    }

    [Fact]
    public void Project_references_are_not_packages()
    {
        const string json = """
        {
          "version": 3,
          "targets": {
            "net10.0": {
              "Other.Project/1.0.0": { "type": "project" },
              "Real.Package/2.0.0": { "type": "package" }
            }
          },
          "projectFileDependencyGroups": { "net10.0": ["Other.Project >= 1.0.0", "Real.Package >= 2.0.0"] }
        }
        """;

        TargetGraph target = Assert.Single(NuGetAssetsParser.Parse(json, "x.json", "p").Targets);

        ResolvedPackage only = Assert.Single(target.Packages);
        Assert.Equal("Real.Package", only.Id);
    }

    [Fact]
    public void Runtime_specific_targets_use_the_framework_for_direct_dependencies()
    {
        const string json = """
        {
          "version": 3,
          "targets": {
            "net10.0": { "Pkg/1.0.0": { "type": "package" } },
            "net10.0/win-x64": { "Pkg/1.0.0": { "type": "package" } }
          },
          "projectFileDependencyGroups": { "net10.0": ["Pkg >= 1.0.0"] }
        }
        """;

        ProjectGraph graph = NuGetAssetsParser.Parse(json, "x.json", "p");

        Assert.Equal(2, graph.Targets.Count);
        Assert.All(graph.Targets, t => Assert.True(Assert.Single(t.Packages).IsDirect));
    }

    [Fact]
    public void Rejects_text_that_is_not_json()
    {
        Assert.Throws<InvalidInputException>(() => NuGetAssetsParser.Parse("{ not json", "x.json", "p"));
    }

    [Fact]
    public void Rejects_json_that_is_not_an_assets_file()
    {
        Assert.Throws<InvalidInputException>(() => NuGetAssetsParser.Parse("[]", "x.json", "p"));
        Assert.Throws<InvalidInputException>(() => NuGetAssetsParser.Parse("""{"name":"x"}""", "x.json", "p"));
    }

    [Fact]
    public void Rejects_unsupported_assets_versions()
    {
        Assert.Throws<InvalidInputException>(() => NuGetAssetsParser.Parse("""{"version":2}""", "x.json", "p"));
    }

    [Fact]
    public void Rejects_malformed_package_keys()
    {
        const string json = """{"version":3,"targets":{"net10.0":{"NoVersionHere":{"type":"package"}}}}""";

        Assert.Throws<InvalidInputException>(() => NuGetAssetsParser.Parse(json, "x.json", "p"));
    }

    [Fact]
    public void Rejects_excessively_nested_documents()
    {
        string deep = new string('[', 200) + new string(']', 200);

        Assert.Throws<InvalidInputException>(() => NuGetAssetsParser.Parse(deep, "x.json", "p"));
    }

    [Fact]
    public void Json_output_is_byte_for_byte_stable()
    {
        ToolInfo tool = new("deprisk", "0.0.0-test");
        ScanResult first = new(1, tool, "nuget", [ParseFixture()]);
        ScanResult second = new(1, tool, "nuget", [ParseFixture()]);

        string a = ScanResultJson.Serialize(first);

        Assert.Equal(a, ScanResultJson.Serialize(second));
        Assert.DoesNotContain("\r", a);
        Assert.Contains("\"schemaVersion\": 1", a);
        Assert.Contains("\"isDirect\": true", a);
        Assert.Contains("[1.0.0, 2.0.0)", a);
    }
}

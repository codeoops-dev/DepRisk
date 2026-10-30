using DepRisk.Core;
using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Data.NuGet;
using DepRisk.Data.Osv;
using Xunit;

namespace DepRisk.Data.Tests;

public class ProjectFileTests
{
    private static string Assets(string? projectPath)
    {
        string restore = projectPath is null
            ? "\"projectName\": \"App\""
            : $"\"projectName\": \"App\", \"projectPath\": {System.Text.Json.JsonSerializer.Serialize(projectPath)}";

        return $$"""
            { "version": 3, "targets": { "net10.0": { "Pkg/1.0.0": { "type": "package" } } },
              "projectFileDependencyGroups": { "net10.0": ["Pkg >= 1.0.0"] },
              "project": { "restore": { {{restore}} } } }
            """;
    }

    [Theory]
    [InlineData("/home/dev/work/src/App/App.csproj", "App.csproj")]
    [InlineData("C:\\Users\\Dev Name\\src\\App\\App.fsproj", "App.fsproj")]
    [InlineData("App.vbproj", "App.vbproj")]
    [InlineData("/a/b/My App.csproj", "My App.csproj")]
    public void The_parser_keeps_only_the_file_name_of_the_restore_project_path(string projectPath, string expected)
    {
        ProjectGraph graph = NuGetAssetsParser.Parse(Assets(projectPath), "obj/project.assets.json", "x");

        Assert.Equal(expected, graph.ProjectFile);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/dir/")]
    [InlineData("C:\\dir\\")]
    public void A_missing_or_empty_name_gives_no_project_file(string? projectPath)
    {
        ProjectGraph graph = NuGetAssetsParser.Parse(Assets(projectPath), "obj/project.assets.json", "x");

        Assert.Null(graph.ProjectFile);
    }

    [Fact]
    public void A_name_with_control_characters_or_excessive_length_is_dropped()
    {
        Assert.Null(NuGetAssetsParser.Parse(Assets("/a/b\u001b[31m.csproj"), "obj/project.assets.json", "x").ProjectFile);
        Assert.Null(NuGetAssetsParser.Parse(Assets("/a/" + new string('x', 300) + ".csproj"), "obj/project.assets.json", "x").ProjectFile);
    }

    [Theory]
    [InlineData("src/App/obj/project.assets.json", "App.csproj", "src/App/App.csproj")]
    [InlineData("obj/project.assets.json", "App.csproj", "App.csproj")]
    [InlineData("a/b/c/obj/project.assets.json", "C.fsproj", "a/b/c/C.fsproj")]
    public void The_project_file_is_the_assets_directory_above_obj_plus_the_name(string assets, string name, string expected)
    {
        Assert.Equal(expected, ScanService.ComposeProjectFile(assets, name));
    }

    [Theory]
    [InlineData("project.assets.json", "App.csproj")]
    [InlineData("src/App/bin/project.assets.json", "App.csproj")]
    [InlineData("src/App/obj/project.assets.json", null)]
    [InlineData("src/App/Xobj/project.assets.json", "App.csproj")]
    public void When_the_layout_is_unknown_or_the_name_is_missing_there_is_no_project_file(string assets, string? name)
    {
        Assert.Null(ScanService.ComposeProjectFile(assets, name));
    }

    [Fact]
    public void Findings_point_at_the_project_file_and_fall_back_to_the_assets_file()
    {
        ToolInfo tool = new("deprisk", "0.0.0-test");
        ProjectGraph withFile = NuGetAssetsParser.Parse(Assets("/x/App.csproj"), "obj/project.assets.json", "x") with { ProjectFile = "src/App/App.csproj" };
        ProjectGraph without = NuGetAssetsParser.Parse(Assets(null), "lib/obj/project.assets.json", "x");
        ScanResult scan = new(1, tool, "nuget", [withFile with { Name = "WithFile" }, without with { Name = "Without" }]);

        Advisory advisory = new(
            "A-1",
            [],
            null,
            false,
            [],
            null,
            [new AffectedPackage("NuGet", "Pkg", [new AffectedRange("ECOSYSTEM", [new RangeEvent("introduced", "0"), new RangeEvent("fixed", "2.0.0")])], [])]);

        FindingsResult result = FindingsService.Compute(
            scan,
            new AdvisorySnapshot([advisory], "osv", new string('a', 64), 0, 0, 0, []),
            tool);

        Finding finding = Assert.Single(result.Findings);
        Assert.Equal(
            new[] { "lib/obj/project.assets.json", "src/App/App.csproj" },
            finding.Locations.Select(l => l.ProjectFile).Order(StringComparer.Ordinal).ToArray());
    }
}

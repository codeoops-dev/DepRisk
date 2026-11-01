using DepRisk.Core.Model;
using DepRisk.Data.NuGet;
using Xunit;

namespace DepRisk.Data.Tests;

public class RequestedConstraintTests
{
    private static ProjectGraph Parse(string groups) =>
        NuGetAssetsParser.Parse(
            $$"""
            { "version": 3,
              "targets": { "net10.0": {
                "Direct.One/1.2.0": { "type": "package" },
                "Direct.Two/2.0.0": { "type": "package" },
                "Transitive/3.0.0": { "type": "package" } } },
              "projectFileDependencyGroups": { "net10.0": {{groups}} } }
            """,
            "obj/project.assets.json",
            "x");

    private static ResolvedPackage Package(ProjectGraph graph, string id) =>
        Assert.Single(graph.Targets).Packages.Single(p => p.Id == id);

    [Fact]
    public void The_requested_constraint_of_a_direct_dependency_is_kept_as_written()
    {
        ProjectGraph graph = Parse("""["Direct.One >= 1.2.0", "Direct.Two [2.0.0, 3.0.0)"]""");

        Assert.Equal(">= 1.2.0", Package(graph, "Direct.One").Requested);
        Assert.Equal("[2.0.0, 3.0.0)", Package(graph, "Direct.Two").Requested);
    }

    [Fact]
    public void Transitive_packages_have_no_requested_constraint()
    {
        ProjectGraph graph = Parse("""["Direct.One >= 1.2.0"]""");

        ResolvedPackage transitive = Package(graph, "Transitive");

        Assert.False(transitive.IsDirect);
        Assert.Null(transitive.Requested);
    }

    [Fact]
    public void A_direct_dependency_listed_without_a_constraint_is_direct_with_no_requested_text()
    {
        ProjectGraph graph = Parse("""["Direct.One"]""");

        ResolvedPackage package = Package(graph, "Direct.One");

        Assert.True(package.IsDirect);
        Assert.Null(package.Requested);
    }

    [Fact]
    public void Constraints_with_control_characters_or_excessive_length_are_dropped_but_the_package_stays_direct()
    {
        ProjectGraph graph = Parse("[\"Direct.One >= 1.0\\u001b[31m\", \"Direct.Two >= " + new string('9', 300) + "\"]");

        Assert.True(Package(graph, "Direct.One").IsDirect);
        Assert.Null(Package(graph, "Direct.One").Requested);
        Assert.True(Package(graph, "Direct.Two").IsDirect);
        Assert.Null(Package(graph, "Direct.Two").Requested);
    }

    [Fact]
    public void Direct_dependency_ids_match_ignoring_case()
    {
        ProjectGraph graph = Parse("""["direct.one >= 1.2.0"]""");

        Assert.True(Package(graph, "Direct.One").IsDirect);
        Assert.Equal(">= 1.2.0", Package(graph, "Direct.One").Requested);
    }
}

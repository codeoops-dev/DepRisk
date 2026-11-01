using DepRisk.Core.Hypergraph;
using DepRisk.Core.Model;
using Xunit;

namespace DepRisk.Core.Tests;

public class HypergraphBuilderTests
{
    private static ResolvedPackage Pkg(string id, string version, bool direct = false, string? requested = null, params (string Id, string Range)[] deps) =>
        new(id, version, direct, deps.Select(d => new DependencyRef(d.Id, d.Range)).ToList(), requested);

    private static TargetHypergraph Build(params ResolvedPackage[] packages) =>
        HypergraphBuilder.BuildTarget("App", new TargetGraph("net10.0", packages));

    private static ResolvedPackage[] Sample() =>
    [
        Pkg("Lib.A", "1.0.0", true, ">= 1.0.0", ("Lib.B", "[1.0.0, 2.0.0)"), ("Lib.C", "2.0.0")),
        Pkg("Lib.B", "1.5.0", false, null, ("Lib.C", "2.0.0")),
        Pkg("Lib.C", "2.1.0"),
        Pkg("Lib.D", "3.0.0", true, ">= 3.0.0"),
    ];

    [Fact]
    public void Nodes_are_all_resolved_packages_sorted_with_direct_flag_and_requested_constraint()
    {
        TargetHypergraph graph = Build(Sample().Reverse().ToArray());

        Assert.Equal(new[] { "Lib.A", "Lib.B", "Lib.C", "Lib.D" }, graph.Nodes.Select(n => n.Id).ToArray());
        Assert.Equal(new[] { true, false, false, true }, graph.Nodes.Select(n => n.IsDirect).ToArray());
        Assert.Equal(">= 1.0.0", graph.Nodes[0].Requested);
        Assert.Null(graph.Nodes[1].Requested);
    }

    [Fact]
    public void There_is_one_project_hyperedge_and_one_per_package_that_requires_something()
    {
        TargetHypergraph graph = Build(Sample());

        Assert.Equal(new[] { "project:App", "Lib.A@1.0.0", "Lib.B@1.5.0" }, graph.Hyperedges.Select(e => e.Id).ToArray());
        Assert.Equal(new[] { "project", "package", "package" }, graph.Hyperedges.Select(e => e.Kind).ToArray());
    }

    [Fact]
    public void The_project_hyperedge_constrains_the_project_and_its_direct_dependencies()
    {
        Hyperedge project = Build(Sample()).Hyperedges[0];

        Assert.Equal("App", project.Owner);
        Assert.Equal(new[] { "App", "Lib.A", "Lib.D" }, project.Scope.ToArray());
        Assert.Equal(3, project.Arity);
        Assert.Equal(new[] { ">= 1.0.0", ">= 3.0.0" }, project.Requires.Select(r => r.Range).ToArray());
        Assert.Equal(new[] { "1.0.0", "3.0.0" }, project.Requires.Select(r => r.Resolved).ToArray());
        Assert.True(project.Satisfied);
    }

    [Fact]
    public void A_package_hyperedge_has_the_owner_and_everything_it_requires_in_its_scope()
    {
        Hyperedge a = Build(Sample()).Hyperedges.Single(e => e.Id == "Lib.A@1.0.0");

        Assert.Equal("Lib.A@1.0.0", a.Owner);
        Assert.Equal(new[] { "Lib.A", "Lib.B", "Lib.C" }, a.Scope.ToArray());
        Assert.Equal(3, a.Arity);
        Assert.All(a.Requires, r => Assert.True(r.Satisfied));
        Assert.Equal(new[] { "1.5.0", "2.1.0" }, a.Requires.Select(r => r.Resolved).ToArray());
        Assert.True(a.Satisfied);
    }

    [Fact]
    public void A_resolved_version_outside_the_declared_range_is_a_violation()
    {
        TargetHypergraph graph = Build(
            Pkg("Lib.A", "1.0.0", true, ">= 1.0.0", ("Lib.B", "[1.0.0, 1.2.0)")),
            Pkg("Lib.B", "1.5.0"));

        Hyperedge a = graph.Hyperedges.Single(e => e.Id == "Lib.A@1.0.0");
        Requirement violated = Assert.Single(a.Requires);

        Assert.False(violated.Satisfied);
        Assert.Equal("1.5.0", violated.Resolved);
        Assert.False(a.Satisfied);
        Assert.Equal(1, graph.Stats.Violated);
        Assert.Equal(0, graph.Stats.Unresolved);
    }

    [Fact]
    public void Requirements_that_cannot_be_decided_are_null_never_guessed()
    {
        TargetHypergraph graph = Build(
            Pkg("Lib.A", "1.0.0", true, ">= 1.0.0",
                ("Lib.Missing", "1.0.0"),
                ("Lib.Weird", "1.*"),
                ("Lib.NoRange", "")),
            Pkg("Lib.Weird", "1.0.0"),
            Pkg("Lib.NoRange", "1.0.0"));

        Hyperedge a = graph.Hyperedges.Single(e => e.Id == "Lib.A@1.0.0");

        Assert.All(a.Requires, r => Assert.Null(r.Satisfied));
        Assert.Null(a.Satisfied);
        Assert.Null(a.Requires.Single(r => r.Package == "Lib.Missing").Resolved);
        Assert.Equal("1.0.0", a.Requires.Single(r => r.Package == "Lib.Weird").Resolved);
        Assert.Equal(3, graph.Stats.Unresolved);
    }

    [Fact]
    public void A_violation_wins_over_undecided_requirements_in_the_edge_verdict()
    {
        TargetHypergraph graph = Build(
            Pkg("Lib.A", "1.0.0", true, ">= 1.0.0", ("Lib.B", "[9.0.0]"), ("Lib.Missing", "1.0.0")),
            Pkg("Lib.B", "1.5.0"));

        Assert.False(graph.Hyperedges.Single(e => e.Id == "Lib.A@1.0.0").Satisfied);
    }

    [Fact]
    public void Package_ids_match_ignoring_case()
    {
        TargetHypergraph graph = Build(
            Pkg("Lib.A", "1.0.0", true, ">= 1.0.0", ("lib.b", "[1.0.0, 2.0.0)")),
            Pkg("Lib.B", "1.5.0"));

        Requirement requirement = Assert.Single(graph.Hyperedges.Single(e => e.Id == "Lib.A@1.0.0").Requires);

        Assert.True(requirement.Satisfied);
        Assert.Equal("1.5.0", requirement.Resolved);
    }

    [Fact]
    public void Without_direct_packages_there_is_no_project_hyperedge()
    {
        TargetHypergraph graph = Build(Pkg("Lib.A", "1.0.0", false, null, ("Lib.B", "1.0.0")), Pkg("Lib.B", "1.0.0"));

        Assert.DoesNotContain(graph.Hyperedges, e => e.Kind == "project");
        Assert.Single(graph.Hyperedges);
    }

    [Fact]
    public void Packages_without_requirements_have_no_hyperedge_and_an_empty_graph_is_valid()
    {
        TargetHypergraph single = Build(Pkg("Lib.A", "1.0.0"));
        TargetHypergraph empty = Build();

        Assert.Empty(single.Hyperedges);
        Assert.Equal(1, single.Stats.Nodes);
        Assert.Equal(0, single.Stats.MaxArity);
        Assert.Empty(empty.Nodes);
        Assert.Equal(0, empty.Stats.Hyperedges);
    }

    [Fact]
    public void Stats_count_nodes_edges_arity_requirements_and_shared_requirements()
    {
        HypergraphStats stats = Build(Sample()).Stats;

        Assert.Equal(4, stats.Nodes);
        Assert.Equal(2, stats.DirectNodes);
        Assert.Equal(3, stats.Hyperedges);
        Assert.Equal(3, stats.MaxArity);
        Assert.Equal(2 + 2 + 1, stats.Requirements);
        Assert.Equal(0, stats.Violated);
        Assert.Equal(0, stats.Unresolved);

        // Lib.C is required by Lib.A and by Lib.B; Lib.B is required by Lib.A and the project does not require it.
        Assert.Equal(1, stats.SharedRequirements);
    }

    [Fact]
    public void A_package_required_twice_by_the_same_edge_counts_once_for_sharing()
    {
        TargetHypergraph graph = Build(
            Pkg("Lib.A", "1.0.0", true, ">= 1.0.0", ("Lib.B", "1.0.0"), ("lib.b", "1.0.0")),
            Pkg("Lib.B", "1.0.0"));

        Assert.Equal(0, graph.Stats.SharedRequirements);
    }

    [Fact]
    public void The_result_does_not_depend_on_input_order()
    {
        ResolvedPackage[] packages = Sample();
        Random random = new(11);
        string expected = Describe(Build(packages));

        for (int i = 0; i < 10; i++)
        {
            Assert.Equal(expected, Describe(Build(packages.OrderBy(_ => random.Next()).ToArray())));
        }
    }

    [Fact]
    public void Several_projects_and_targets_are_built_independently()
    {
        ToolInfo tool = new("deprisk", "0.0.0-test");
        ScanResult scan = new(
            1,
            tool,
            "nuget",
            [
                new ProjectGraph("One", "One/obj/project.assets.json", [new TargetGraph("net10.0", Sample()), new TargetGraph("net10.0/linux-x64", Sample())], "One/One.csproj"),
                new ProjectGraph("Two", "Two/obj/project.assets.json", [new TargetGraph("net10.0", [Pkg("Only", "1.0.0", true, ">= 1.0.0")])]),
            ]);

        HypergraphResult result = HypergraphBuilder.Build(scan);

        Assert.Equal(1, result.SchemaVersion);
        Assert.Equal(new[] { "One", "Two" }, result.Projects.Select(p => p.Name).ToArray());
        Assert.Equal("One/One.csproj", result.Projects[0].ProjectFile);
        Assert.Equal(new[] { "net10.0", "net10.0/linux-x64" }, result.Projects[0].Targets.Select(t => t.Name).ToArray());
        Assert.Equal("project:Two", Assert.Single(result.Projects[1].Targets[0].Hyperedges).Id);
    }

    private static string Describe(TargetHypergraph graph) =>
        string.Join(
            ";",
            graph.Hyperedges.Select(e => $"{e.Id}[{string.Join(',', e.Scope)}]{string.Join(',', e.Requires.Select(r => $"{r.Package}:{r.Satisfied}"))}"));
}

using DepRisk.Core.Hypergraph;
using DepRisk.Core.Model;
using Xunit;

namespace DepRisk.Core.Tests;

public class NpmHypergraphBuilderTests
{
    private static ResolvedPackage Pkg(string path, string id, string version, bool direct = false, string? requested = null, params (string Name, string Range)[] deps) =>
        new(id, version, direct, deps.Select(d => new DependencyRef(d.Name, d.Range)).ToList(), requested, path);

    private static TargetHypergraph Build(params ResolvedPackage[] packages) =>
        NpmHypergraphBuilder.BuildTarget("App", new TargetGraph("npm", packages));

    private static Hyperedge Edge(TargetHypergraph graph, string id) => Assert.Single(graph.Hyperedges, e => e.Id == id);

    private static Dictionary<string, ResolvedPackage> Index(params ResolvedPackage[] packages) => packages.ToDictionary(p => p.Path!, StringComparer.Ordinal);

    // --- Node's lookup ---

    [Theory]
    [InlineData("node_modules/a", "b", "node_modules/b")]                                          // a sibling at the top level
    [InlineData("node_modules/a", "c", "node_modules/a/node_modules/c")]                           // nested inside the requirer first
    [InlineData("node_modules/a/node_modules/c", "b", "node_modules/b")]                           // walks up past the requirer's parent
    [InlineData("node_modules/a/node_modules/c", "d", "node_modules/a/node_modules/d")]            // a sibling inside the same parent
    [InlineData("node_modules/x/node_modules/y/node_modules/z", "b", "node_modules/b")]            // several levels up
    [InlineData("packages/web/node_modules/debug", "ms", "packages/web/node_modules/ms")]          // a workspace member's own node_modules first
    [InlineData("packages/web/node_modules/debug", "b", "node_modules/b")]                         // then the project's
    [InlineData("node_modules/@s/p", "b", "node_modules/b")]                                       // a scoped requirer
    [InlineData("node_modules/a", "@s/q", "node_modules/@s/q")]                                    // a scoped requirement
    public void Node_lookup_finds_the_nearest_installed_copy(string requirer, string name, string expected)
    {
        Dictionary<string, ResolvedPackage> byPath = Index(
            Pkg("node_modules/a", "a", "1.0.0"),
            Pkg("node_modules/b", "b", "1.0.0"),
            Pkg("node_modules/a/node_modules/c", "c", "1.0.0"),
            Pkg("node_modules/a/node_modules/d", "d", "1.0.0"),
            Pkg("node_modules/@s/q", "@s/q", "1.0.0"),
            Pkg("packages/web/node_modules/ms", "ms", "2.0.0"));

        Assert.Equal(expected, NpmHypergraphBuilder.Resolve(requirer, name, byPath)!.Path);
    }

    [Fact]
    public void Nothing_is_found_when_nothing_is_installed_in_any_enclosing_directory()
    {
        Dictionary<string, ResolvedPackage> byPath = Index(Pkg("node_modules/a/node_modules/c", "c", "1.0.0"), Pkg("node_modules/a", "a", "1.0.0"));

        // c is only installed inside a, so a sibling of a cannot see it.
        Assert.Null(NpmHypergraphBuilder.Resolve("node_modules/b", "c", byPath));
        Assert.Null(NpmHypergraphBuilder.Resolve("node_modules/a", "zzz", byPath));
    }

    [Fact]
    public void A_directory_named_node_modules_is_never_searched_itself()
    {
        // "node_modules/node_modules/x" would be wrong: Node skips directories that are themselves named node_modules.
        Dictionary<string, ResolvedPackage> byPath = Index(Pkg("node_modules/node_modules/x", "x", "1.0.0"));

        Assert.Null(NpmHypergraphBuilder.Resolve("node_modules/a", "x", byPath));
    }

    // --- the graph ---

    [Fact]
    public void The_same_package_at_two_places_is_two_nodes_and_each_requirement_goes_to_the_right_one()
    {
        TargetHypergraph graph = Build(
            Pkg("node_modules/debug", "debug", "2.6.9", true, "2.6.9", ("ms", "2.0.0")),
            Pkg("node_modules/debug/node_modules/ms", "ms", "2.0.0"),
            Pkg("node_modules/send", "send", "0.18.0", true, "0.18.0", ("ms", "2.1.3")),
            Pkg("node_modules/ms", "ms", "2.1.3"));

        Assert.Equal(
            new[] { "node_modules/debug", "node_modules/debug/node_modules/ms", "node_modules/ms", "node_modules/send" },
            graph.Nodes.Select(n => n.Path!).ToArray());

        Requirement fromDebug = Assert.Single(Edge(graph, "node_modules/debug").Requires);
        Assert.Equal("node_modules/debug/node_modules/ms", fromDebug.ResolvedPath);
        Assert.Equal("2.0.0", fromDebug.Resolved);
        Assert.True(fromDebug.Satisfied);

        Requirement fromSend = Assert.Single(Edge(graph, "node_modules/send").Requires);
        Assert.Equal("node_modules/ms", fromSend.ResolvedPath);
        Assert.Equal("2.1.3", fromSend.Resolved);
        Assert.True(fromSend.Satisfied);
    }

    [Fact]
    public void A_requirement_the_installed_version_does_not_meet_is_violated()
    {
        TargetHypergraph graph = Build(
            Pkg("node_modules/a", "a", "1.0.0", false, null, ("b", "^2.0.0")),
            Pkg("node_modules/b", "b", "1.9.9"));

        Hyperedge edge = Edge(graph, "node_modules/a");

        Assert.False(Assert.Single(edge.Requires).Satisfied);
        Assert.False(edge.Satisfied);
        Assert.Equal(1, graph.Stats.Violated);
    }

    [Theory]
    [InlineData("latest")]
    [InlineData("github:user/repo#semver:^1")]
    [InlineData("file:../b")]
    [InlineData("workspace:*")]
    [InlineData("npm:b")]
    public void A_specifier_that_is_not_a_range_is_undecided_never_satisfied(string range)
    {
        TargetHypergraph graph = Build(
            Pkg("node_modules/a", "a", "1.0.0", false, null, ("b", range)),
            Pkg("node_modules/b", "b", "1.0.0"));

        Requirement requirement = Assert.Single(Edge(graph, "node_modules/a").Requires);

        Assert.Null(requirement.Satisfied);
        Assert.Equal("1.0.0", requirement.Resolved);
        Assert.Null(Edge(graph, "node_modules/a").Satisfied);
        Assert.Equal(1, graph.Stats.Unresolved);
    }

    [Fact]
    public void A_requirement_nothing_resolves_is_undecided_and_has_no_resolved_instance()
    {
        TargetHypergraph graph = Build(Pkg("node_modules/a", "a", "1.0.0", false, null, ("missing", "^1.0.0")));

        Requirement requirement = Assert.Single(Edge(graph, "node_modules/a").Requires);

        Assert.Null(requirement.Resolved);
        Assert.Null(requirement.ResolvedPath);
        Assert.Null(requirement.Satisfied);
    }

    [Fact]
    public void An_alias_install_is_checked_against_the_range_inside_the_alias()
    {
        TargetHypergraph graph = Build(
            Pkg("node_modules/strip-ansi-cjs", "strip-ansi", "6.0.1", true, "npm:strip-ansi@^6.0.1"),
            Pkg("node_modules/host", "host", "1.0.0", false, null, ("strip-ansi-cjs", "npm:strip-ansi@^7.0.0")));

        Hyperedge project = Edge(graph, "project:App");
        Requirement ask = Assert.Single(project.Requires);

        Assert.Equal("strip-ansi-cjs", ask.Package);   // the name the project wrote
        Assert.Equal("6.0.1", ask.Resolved);
        Assert.True(ask.Satisfied);

        Assert.False(Assert.Single(Edge(graph, "node_modules/host").Requires).Satisfied);   // ^7 is not met by 6.0.1
    }

    [Fact]
    public void The_project_hyperedge_lists_every_direct_package_including_copies_in_workspace_members()
    {
        TargetHypergraph graph = Build(
            Pkg("node_modules/debug", "debug", "4.3.4", true, "4.3.4"),
            Pkg("packages/web/node_modules/debug", "debug", "2.6.9", true, "2.6.9"),
            Pkg("node_modules/ms", "ms", "2.1.3", true, "2.1.3"),
            Pkg("node_modules/other", "other", "1.0.0"));

        Hyperedge project = Edge(graph, "project:App");

        Assert.Equal("project", project.Kind);
        Assert.Null(project.Path);
        Assert.Equal(
            new[] { "node_modules/debug", "packages/web/node_modules/debug", "node_modules/ms" },
            project.Requires.Select(r => r.ResolvedPath!).ToArray());
        Assert.Equal(new[] { "App", "debug", "debug", "ms" }, project.Scope.ToArray());
        Assert.True(project.Satisfied);
    }

    [Fact]
    public void Package_hyperedges_carry_their_path_and_owner_and_edges_are_sorted_by_path()
    {
        TargetHypergraph graph = Build(
            Pkg("node_modules/z", "z", "1.0.0", false, null, ("a", "*")),
            Pkg("node_modules/a", "a", "1.0.0", false, null, ("z", "*")));

        Assert.Equal(new[] { "node_modules/a", "node_modules/z" }, graph.Hyperedges.Select(e => e.Id).ToArray());
        Hyperedge edge = graph.Hyperedges[0];
        Assert.Equal("package", edge.Kind);
        Assert.Equal("a@1.0.0", edge.Owner);
        Assert.Equal("node_modules/a", edge.Path);
        Assert.Equal(new[] { "a", "z" }, edge.Scope.ToArray());
        Assert.Equal(2, edge.Arity);
    }

    [Fact]
    public void Shared_requirements_count_installed_instances_not_names()
    {
        // Two requirers resolve "ms" to two different instances: nothing is shared. Two resolve to one: shared.
        TargetHypergraph apart = Build(
            Pkg("node_modules/a", "a", "1.0.0", false, null, ("ms", "*")),
            Pkg("node_modules/b", "b", "1.0.0", false, null, ("ms", "*")),
            Pkg("node_modules/a/node_modules/ms", "ms", "2.0.0"),
            Pkg("node_modules/b/node_modules/ms", "ms", "2.1.3"));

        TargetHypergraph together = Build(
            Pkg("node_modules/a", "a", "1.0.0", false, null, ("ms", "*")),
            Pkg("node_modules/b", "b", "1.0.0", false, null, ("ms", "*")),
            Pkg("node_modules/ms", "ms", "2.1.3"));

        Assert.Equal(0, apart.Stats.SharedRequirements);
        Assert.Equal(1, together.Stats.SharedRequirements);
    }

    [Fact]
    public void The_build_is_deterministic_whatever_the_input_order()
    {
        ResolvedPackage[] packages =
        [
            Pkg("node_modules/a", "a", "1.0.0", true, "^1", ("b", "^1")),
            Pkg("node_modules/b", "b", "1.2.0", false, null, ("c", "~2.0.0")),
            Pkg("node_modules/b/node_modules/c", "c", "2.0.5"),
        ];

        TargetHypergraph forward = Build(packages);
        TargetHypergraph backward = Build(packages.Reverse().ToArray());

        Assert.Equal(forward.Nodes, backward.Nodes);
        Assert.Equal(forward.Hyperedges.Select(e => (e.Id, e.Satisfied)), backward.Hyperedges.Select(e => (e.Id, e.Satisfied)));
    }

    [Fact]
    public void A_scan_of_the_npm_ecosystem_is_built_by_the_npm_rules_and_nuget_still_by_its_own()
    {
        ScanResult npm = new(ScanResult.CurrentSchemaVersion, new ToolInfo("deprisk", "t"), "npm",
            [new ProjectGraph("App", "package-lock.json", [new TargetGraph("npm", [Pkg("node_modules/a", "a", "1.0.0", true, "^1")])])]);

        HypergraphResult result = HypergraphBuilder.Build(npm);

        Assert.Equal("npm", result.Ecosystem);
        Assert.Equal("node_modules/a", result.Projects[0].Targets[0].Nodes[0].Path);
        Assert.Equal("node_modules/a", Assert.Single(result.Projects[0].Targets[0].Hyperedges[0].Requires).ResolvedPath);
    }

    [Fact]
    public void Packages_without_a_path_are_not_placed_in_the_tree()
    {
        TargetHypergraph graph = NpmHypergraphBuilder.BuildTarget(
            "App",
            new TargetGraph("npm", [new ResolvedPackage("a", "1.0.0", true, [], "^1")]));

        Assert.Empty(graph.Nodes);
        Assert.Empty(graph.Hyperedges);
    }
}

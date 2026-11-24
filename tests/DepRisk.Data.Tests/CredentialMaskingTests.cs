using DepRisk.Core.Model;
using DepRisk.Data.Npm;
using DepRisk.Data.NuGet;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>A credential in a URL in a dependency file never reaches the graph the parsers return (ADR 0027).</summary>
public class CredentialMaskingTests
{
    private const string Secret = "TOKEN123";
    private const string Url = "git+https://user:" + Secret + "@example.com/org/a.git";
    private const string Masked = "git+https://***@example.com/org/a.git";

    private static IEnumerable<string> Strings(ProjectGraph graph) =>
        graph.Targets.SelectMany(t => t.Packages).SelectMany(p =>
            new[] { p.Id, p.Version, p.Requested ?? string.Empty, p.Path ?? string.Empty }.Concat(p.Dependencies.SelectMany(d => new[] { d.Id, d.Range })));

    private static void AssertClean(ProjectGraph graph)
    {
        Assert.DoesNotContain(Strings(graph), s => s.Contains(Secret, StringComparison.Ordinal));
        Assert.DoesNotContain(Secret, graph.Name);
    }

    [Fact]
    public void An_npm_lockfile_version_3_masks_the_requested_range_and_the_dependency_ranges()
    {
        string json = $$"""
            { "name": "demo", "lockfileVersion": 3, "packages": {
                "": { "name": "demo", "dependencies": { "a": "{{Url}}" } },
                "node_modules/a": { "version": "1.0.0", "dependencies": { "b": "{{Url}}#semver:^1" },
                                    "optionalDependencies": { "c": "https://u:{{Secret}}@h/c.tgz" } },
                "node_modules/b": { "version": "1.2.0" },
                "node_modules/c": { "version": "1.0.0" } } }
            """;

        ProjectGraph graph = NpmLockParser.Parse(json, "package-lock.json", "demo");

        AssertClean(graph);
        ResolvedPackage a = graph.Targets[0].Packages.Single(p => p.Path == "node_modules/a");
        Assert.Equal(Masked, a.Requested);
        Assert.Equal(Masked + "#semver:^1", a.Dependencies.Single(d => d.Id == "b").Range);
        Assert.Equal("https://***@h/c.tgz", a.Dependencies.Single(d => d.Id == "c").Range);
    }

    [Fact]
    public void An_npm_version_that_is_a_url_is_masked_in_version_2_and_3()
    {
        string json = $$"""
            { "lockfileVersion": 2, "packages": { "": {}, "node_modules/a": { "version": "https://u:{{Secret}}@h/a.tgz" } } }
            """;

        ProjectGraph graph = NpmLockParser.Parse(json, "package-lock.json", "demo");

        AssertClean(graph);
        Assert.Equal("https://***@h/a.tgz", graph.Targets[0].Packages.Single().Version);
    }

    [Fact]
    public void An_npm_lockfile_version_1_masks_requires_and_what_the_package_json_asks_for()
    {
        string lockJson = $$"""
            { "lockfileVersion": 1, "dependencies": {
                "a": { "version": "1.0.0", "requires": { "b": "{{Url}}" } },
                "b": { "version": "git+https://user:{{Secret}}@example.com/org/b.git#abc" } } }
            """;
        string manifest = $$"""{ "dependencies": { "a": "{{Url}}" } }""";

        ProjectGraph graph = NpmLockParser.Parse(lockJson, "package-lock.json", "demo", () => manifest);

        AssertClean(graph);
        Assert.Equal(Masked, graph.Targets[0].Packages.Single(p => p.Id == "a").Requested);
        Assert.Equal(NpmLockParser.UnresolvedVersion, graph.Targets[0].Packages.Single(p => p.Id == "b").Version);
    }

    [Fact]
    public void A_nuget_lock_file_masks_ranges_and_the_requested_range()
    {
        string json = $$"""
            { "version": 1, "dependencies": { "net10.0": {
                "A": { "type": "Direct", "requested": "https://u:{{Secret}}@h/x", "resolved": "1.0.0",
                       "dependencies": { "B": "https://u:{{Secret}}@h/y" } },
                "B": { "type": "Transitive", "resolved": "1.0.0" } } } }
            """;

        ProjectGraph graph = NuGetLockParser.Parse(json, "App/packages.lock.json", "App");

        AssertClean(graph);
        ResolvedPackage a = graph.Targets[0].Packages.Single(p => p.Id == "A");
        Assert.Equal("https://***@h/x", a.Requested);
        Assert.Equal("https://***@h/y", a.Dependencies.Single().Range);
    }

    [Fact]
    public void A_nuget_assets_file_masks_ranges_and_the_requested_range()
    {
        string json = $$"""
            { "version": 3,
              "targets": { "net10.0": { "A/1.0.0": { "type": "package", "dependencies": { "B": "https://u:{{Secret}}@h/y" } }, "B/1.0.0": { "type": "package" } } },
              "projectFileDependencyGroups": { "net10.0": [ "A https://u:{{Secret}}@h/x" ] },
              "project": { "restore": { "projectName": "App" } } }
            """;

        ProjectGraph graph = NuGetAssetsParser.Parse(json, "App/obj/project.assets.json", "App");

        AssertClean(graph);
        ResolvedPackage a = graph.Targets[0].Packages.Single(p => p.Id == "A");
        Assert.Equal("https://***@h/x", a.Requested);
        Assert.Equal("https://***@h/y", a.Dependencies.Single().Range);
    }

    [Fact]
    public void Ordinary_ranges_and_versions_are_not_touched()
    {
        string json = """
            { "lockfileVersion": 3, "packages": {
                "": { "dependencies": { "a": "^1.2.0", "s": "npm:@scope/name@^2.0.0" } },
                "node_modules/a": { "version": "1.2.3", "dependencies": { "b": ">=1.0.0 <2.0.0 || ^3.0.0-beta.1" } },
                "node_modules/b": { "version": "1.5.0" },
                "node_modules/s": { "name": "@scope/name", "version": "2.1.0" } } }
            """;

        ProjectGraph graph = NpmLockParser.Parse(json, "package-lock.json", "demo");

        Assert.Equal("^1.2.0", graph.Targets[0].Packages.Single(p => p.Id == "a").Requested);
        Assert.Equal(">=1.0.0 <2.0.0 || ^3.0.0-beta.1", graph.Targets[0].Packages.Single(p => p.Id == "a").Dependencies.Single().Range);
        Assert.Equal("npm:@scope/name@^2.0.0", graph.Targets[0].Packages.Single(p => p.Id == "@scope/name").Requested);
    }
}

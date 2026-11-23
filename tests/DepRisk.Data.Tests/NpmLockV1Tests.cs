using DepRisk.Core;
using DepRisk.Core.Hypergraph;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.Npm;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>npm lockfileVersion 1 (npm 6 and older). The fixture is written by hand in the format npm 6 writes (no npm 6 was available).</summary>
public sealed class NpmLockV1Tests : IDisposable
{
    private static readonly ToolInfo Tool = new("deprisk", "test");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-npm-v1-" + Guid.NewGuid().ToString("N"));

    public NpmLockV1Tests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private const string Manifest = """
        { "name": "legacy-web", "version": "1.0.0",
          "dependencies": { "express": "^4.16.0", "left-pad": "1.3.0", "aliased": "npm:real-name@^1.0.0" },
          "devDependencies": { "mocha": "^5.0.0" },
          "optionalDependencies": { "fsevents": "^1.2.0" },
          "peerDependencies": { "react": "^16.0.0" } }
        """;

    private const string Lock = """
        { "name": "legacy-web", "version": "1.0.0", "lockfileVersion": 1, "requires": true,
          "dependencies": {
            "express": { "version": "4.16.4", "resolved": "https://registry.npmjs.org/express/-/express-4.16.4.tgz", "integrity": "sha512-x",
              "requires": { "debug": "2.6.9", "left-pad": "^1.0.0" },
              "dependencies": { "debug": { "version": "2.6.9", "requires": { "ms": "2.0.0" } },
                                "ms": { "version": "2.0.0" } } },
            "debug": { "version": "3.1.0", "requires": { "ms": "2.0.0" } },
            "left-pad": { "version": "1.3.0" },
            "mocha": { "version": "5.2.0", "dev": true },
            "aliased": { "version": "npm:real-name@1.2.3" },
            "scoped": { "version": "npm:@scope/other@2.0.0" },
            "from-git": { "version": "git+https://user:secret@example.com/org/repo.git#abc123" },
            "from-file": { "version": "file:../local" },
            "ms": { "version": "2.0.0" },
            "@babel/core": { "version": "7.0.0" } } }
        """;

    private static ProjectGraph Parse(string lockJson, string? manifest = Manifest) =>
        NpmLockParser.Parse(lockJson, "web/package-lock.json", "web", () => manifest);

    private static ResolvedPackage At(ProjectGraph graph, string path) => graph.Targets[0].Packages.Single(p => p.Path == path);

    [Fact]
    public void The_tree_becomes_installed_instances_with_node_style_paths()
    {
        ProjectGraph graph = Parse(Lock);

        Assert.Equal("legacy-web", graph.Name);
        TargetGraph target = Assert.Single(graph.Targets);
        Assert.Equal("npm", target.Name);

        Assert.Equal("2.6.9", At(graph, "node_modules/express/node_modules/debug").Version);
        Assert.Equal("2.0.0", At(graph, "node_modules/express/node_modules/ms").Version);
        Assert.Equal("7.0.0", At(graph, "node_modules/@babel/core").Version);
        Assert.Equal(12, target.Packages.Count);
    }

    [Fact]
    public void Direct_comes_from_the_package_json_and_only_at_the_top_level()
    {
        ProjectGraph graph = Parse(Lock);

        ResolvedPackage express = At(graph, "node_modules/express");
        Assert.True(express.IsDirect);
        Assert.Equal("^4.16.0", express.Requested);

        Assert.True(At(graph, "node_modules/mocha").IsDirect);     // devDependencies count
        Assert.Equal("^5.0.0", At(graph, "node_modules/mocha").Requested);

        Assert.False(At(graph, "node_modules/debug").IsDirect);    // nothing asks for it
        Assert.False(At(graph, "node_modules/express/node_modules/debug").IsDirect);
        Assert.False(At(graph, "node_modules/ms").IsDirect);
    }

    [Fact]
    public void A_peer_dependency_is_not_asked_for_because_npm_6_installed_none()
    {
        string lockJson = """{ "lockfileVersion": 1, "dependencies": { "react": { "version": "16.0.0" } } }""";

        Assert.False(Parse(lockJson).Targets[0].Packages.Single().IsDirect);
    }

    [Fact]
    public void Requires_are_the_dependencies_of_an_installed_package()
    {
        ProjectGraph graph = Parse(Lock);

        ResolvedPackage express = At(graph, "node_modules/express");
        Assert.Equal(["debug", "left-pad"], express.Dependencies.Select(d => d.Id).ToArray());
        Assert.Equal("^1.0.0", express.Dependencies.Single(d => d.Id == "left-pad").Range);
        Assert.Empty(At(graph, "node_modules/ms").Dependencies);
    }

    [Fact]
    public void An_alias_is_the_real_package_and_a_location_is_never_copied_into_the_result()
    {
        ProjectGraph graph = Parse(Lock);

        ResolvedPackage alias = At(graph, "node_modules/aliased");
        Assert.Equal("real-name", alias.Id);
        Assert.Equal("1.2.3", alias.Version);
        Assert.True(alias.IsDirect);

        ResolvedPackage scoped = At(graph, "node_modules/scoped");
        Assert.Equal("@scope/other", scoped.Id);
        Assert.Equal("2.0.0", scoped.Version);

        foreach (string path in new[] { "node_modules/from-git", "node_modules/from-file" })
        {
            ResolvedPackage package = At(graph, path);
            Assert.Equal(NpmLockParser.UnresolvedVersion, package.Version);
            Assert.DoesNotContain("secret", package.Version);
        }

        Assert.Equal("from-git", At(graph, "node_modules/from-git").Id);
    }

    [Fact]
    public void A_package_with_an_unresolved_version_is_counted_as_skipped_and_never_matched()
    {
        ProjectGraph graph = Parse("""{ "lockfileVersion": 1, "dependencies": { "x": { "version": "github:a/b#c" } } }""");

        Assert.False(Ecosystem.Npm.TryParseVersion(graph.Targets[0].Packages.Single().Version, out _));
    }

    [Fact]
    public void The_project_name_comes_from_the_lock_then_the_package_json_then_the_directory()
    {
        Assert.Equal("legacy-web", Parse(Lock).Name);
        Assert.Equal("from-manifest", Parse("""{ "lockfileVersion": 1 }""", """{ "name": "from-manifest" }""").Name);
        Assert.Equal("web", Parse("""{ "lockfileVersion": 1 }""", "{}").Name);
    }

    [Fact]
    public void A_lock_file_without_packages_is_an_empty_graph()
    {
        Assert.Empty(Parse("""{ "lockfileVersion": 1, "requires": true }""", "{}").Targets[0].Packages);
        Assert.Empty(Parse("""{ "lockfileVersion": 1, "dependencies": {} }""", "{}").Targets[0].Packages);
    }

    [Fact]
    public void Without_a_package_json_the_file_is_refused_because_direct_cannot_be_known()
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(Lock, manifest: null));

        Assert.Contains("web/package-lock.json", error.Message);
        Assert.Contains("lockfileVersion 1", error.Message);
        Assert.Contains("web/package.json", error.Message);

        // No provider at all is the same refusal.
        Assert.Contains("package.json", Assert.Throws<InvalidInputException>(() => NpmLockParser.Parse(Lock, "web/package-lock.json", "web")).Message);
    }

    [Theory]
    [InlineData("{ nope", "web/package.json: not valid JSON")]
    [InlineData("[]", "web/package.json: not a package.json")]
    [InlineData("""{ "dependencies": { "bad name!": "1" } }""", "invalid package name")]
    public void A_package_json_that_cannot_be_read_is_an_input_error_naming_it(string manifest, string expected)
    {
        Assert.Contains(expected, Assert.Throws<InvalidInputException>(() => Parse(Lock, manifest)).Message);
    }

    [Theory]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": [] }""", "'dependencies' of the lock file is not an object")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a": "1.0.0" } }""", "is not an object")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a": {} } }""", "no valid 'version'")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a": { "version": 1 } } }""", "no valid 'version'")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a b": { "version": "1.0.0" } } }""", "invalid package name")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a": { "version": "1.0.0", "dependencies": [] } } }""", "node_modules/a' is not an object")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a": { "version": "1.0.0" }, "a": { "version": "2.0.0" } } }""", "duplicate key 'a'")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a": { "version": "1.0.0", "dependencies": { "b": { "version": "1.0.0" }, "b": { "version": "1.0.0" } } } } }""", "duplicate key 'b'")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": { "a": { "version": "1.0.0", "requires": { "bad name": "1" } } } }""", "invalid package name")]
    public void A_broken_version_1_file_is_rejected_with_the_reason(string json, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(json, "{}"));

        Assert.Contains("web/package-lock.json", error.Message);
        Assert.Contains(expected, error.Message);
    }

    [Fact]
    public void Versions_2_and_3_never_ask_for_the_package_json()
    {
        bool asked = false;

        ProjectGraph graph = NpmLockParser.Parse(NpmFixtures.Read(NpmFixtures.Simple), "web/package-lock.json", "web", () =>
        {
            asked = true;
            return null;
        });

        Assert.False(asked);
        Assert.NotEmpty(graph.Targets[0].Packages);
    }

    [Fact]
    public void The_hypergraph_resolves_requirements_the_way_node_does_for_a_version_1_tree()
    {
        ProjectGraph graph = Parse(Lock);

        TargetHypergraph hypergraph = NpmHypergraphBuilder.BuildTarget(graph.Name, graph.Targets[0]);

        Hyperedge express = hypergraph.Hyperedges.Single(e => e.Id == "node_modules/express");
        Requirement debug = express.Requires.Single(r => r.Package == "debug");
        Assert.Equal("node_modules/express/node_modules/debug", debug.ResolvedPath);   // the nested copy wins over the top-level one
        Assert.True(debug.Satisfied);
    }

    // ---- through ScanService: the package.json beside the lock file ----

    private void Put(string relative, string content)
    {
        string path = Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    [Fact]
    public void Scan_reads_the_package_json_beside_a_version_1_lock_file_and_points_findings_at_it()
    {
        Put("web/package-lock.json", Lock);
        Put("web/package.json", Manifest);

        ScanResult result = ScanService.Scan(_root, Tool);

        Assert.Equal("npm", result.Ecosystem);
        ProjectGraph project = Assert.Single(result.Projects);
        Assert.Equal("web/package.json", project.ProjectFile);
        Assert.True(project.Targets[0].Packages.Single(p => p.Path == "node_modules/express").IsDirect);
    }

    [Fact]
    public void Scan_refuses_a_version_1_lock_file_when_the_package_json_is_missing()
    {
        Put("web/package-lock.json", Lock);

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool));

        Assert.Contains("web/package.json", error.Message);
    }

    [Fact]
    public void The_package_json_is_part_of_the_inputs_digest_only_when_it_was_read()
    {
        Put("v1/package-lock.json", Lock);
        Put("v1/package.json", Manifest);
        string v1 = ScanService.ScanDetailed(Path.Combine(_root, "v1"), Tool).InputsDigest;

        Put("v1/package.json", Manifest.Replace("^4.16.0", "^4.17.0", StringComparison.Ordinal));
        Assert.NotEqual(v1, ScanService.ScanDetailed(Path.Combine(_root, "v1"), Tool).InputsDigest);

        Put("v3/package-lock.json", NpmFixtures.Read(NpmFixtures.Simple));
        Put("v3/package.json", "{}");
        string v3 = ScanService.ScanDetailed(Path.Combine(_root, "v3"), Tool).InputsDigest;

        Put("v3/package.json", """{ "name": "changed" }""");
        Assert.Equal(v3, ScanService.ScanDetailed(Path.Combine(_root, "v3"), Tool).InputsDigest);
    }

    [Fact]
    public void A_package_json_that_is_a_link_is_not_followed()
    {
        if (OperatingSystem.IsWindows())
        {
            return;   // creating a link needs a privilege there; the rule is the same code path
        }

        Put("web/package-lock.json", Lock);
        string outside = Path.Combine(_root, "outside.json");
        File.WriteAllText(outside, Manifest);
        File.CreateSymbolicLink(Path.Combine(_root, "web", "package.json"), outside);

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(Path.Combine(_root, "web"), Tool));

        Assert.Contains("package.json", error.Message);
        Assert.Contains("is a link", error.Message);
    }
}

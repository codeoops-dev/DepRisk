using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.Npm;
using Xunit;

namespace DepRisk.Data.Tests;

public class NpmLockParserTests
{
    private static ProjectGraph Parse(string json, string fallback = "fallback") => NpmLockParser.Parse(json, "package-lock.json", fallback);

    private static IReadOnlyList<ResolvedPackage> Packages(ProjectGraph graph) => Assert.Single(graph.Targets).Packages;

    private static ResolvedPackage At(ProjectGraph graph, string path) => Assert.Single(Packages(graph), p => p.Path == path);

    // A minimal valid lock file around the given "packages" entries (JSON text without the root entry).
    private static string Lock(string rootBody, string entries = "") =>
        $$"""
        { "name": "demo", "lockfileVersion": 3, "requires": true, "packages": { "": { {{rootBody}} }{{(entries.Length == 0 ? string.Empty : ", " + entries)}} } }
        """;

    [Fact]
    public void Reads_the_project_name_target_and_every_installed_package_of_a_real_lock_file()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Simple));

        Assert.Equal("sample-web", graph.Name);
        Assert.Equal("package-lock.json", graph.AssetsFile);
        Assert.Null(graph.ProjectFile);

        TargetGraph target = Assert.Single(graph.Targets);
        Assert.Equal("npm", target.Name);

        // 27 entries in the file: the project itself and 26 installed packages.
        Assert.Equal(26, target.Packages.Count);
        Assert.All(target.Packages, p => Assert.StartsWith("node_modules/", p.Path!));
    }

    [Fact]
    public void Direct_packages_are_those_the_project_asks_for_at_the_top_level()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Simple));

        string[] direct = Packages(graph).Where(p => p.IsDirect).Select(p => p.Path!).OrderBy(p => p, StringComparer.Ordinal).ToArray();

        Assert.Equal(
            new[]
            {
                "node_modules/@babel/code-frame",
                "node_modules/debug",
                "node_modules/fsevents",
                "node_modules/ms",
                "node_modules/send",
                "node_modules/strip-ansi-cjs",
            },
            direct);
    }

    [Fact]
    public void The_requested_constraint_is_what_the_project_wrote()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Simple));

        Assert.Equal("2.6.9", At(graph, "node_modules/debug").Requested);
        Assert.Equal("^7.24.0", At(graph, "node_modules/@babel/code-frame").Requested);
        Assert.Equal("^2.1.3", At(graph, "node_modules/ms").Requested);         // a devDependency is a direct dependency
        Assert.Equal("^2.3.3", At(graph, "node_modules/fsevents").Requested);   // so is an optionalDependency
        Assert.Null(At(graph, "node_modules/depd").Requested);
    }

    [Fact]
    public void The_same_package_installed_twice_is_two_entries_told_apart_by_path()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Simple));

        ResolvedPackage nested = At(graph, "node_modules/debug/node_modules/ms");
        ResolvedPackage top = At(graph, "node_modules/ms");

        Assert.Equal("ms", nested.Id);
        Assert.Equal("2.0.0", nested.Version);
        Assert.False(nested.IsDirect);   // inside another package's node_modules
        Assert.Null(nested.Requested);

        Assert.Equal("ms", top.Id);
        Assert.Equal("2.1.3", top.Version);
        Assert.True(top.IsDirect);
    }

    [Fact]
    public void An_alias_install_is_known_by_its_real_name_and_stays_direct_under_the_alias_key()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Simple));

        ResolvedPackage alias = At(graph, "node_modules/strip-ansi-cjs");

        Assert.Equal("strip-ansi", alias.Id);   // advisories are about the real package
        Assert.Equal("6.0.1", alias.Version);
        Assert.True(alias.IsDirect);
        Assert.Equal("npm:strip-ansi@^6.0.1", alias.Requested);
        Assert.Equal(new[] { "ansi-regex" }, alias.Dependencies.Select(d => d.Id).ToArray());
    }

    [Fact]
    public void Dependencies_are_listed_by_name_with_the_range_as_written()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Simple));

        ResolvedPackage send = At(graph, "node_modules/send");

        Assert.Equal(13, send.Dependencies.Count);
        Assert.Equal(new DependencyRef("debug", "2.6.9"), send.Dependencies[0]);
        Assert.Equal(send.Dependencies.OrderBy(d => d.Id, StringComparer.OrdinalIgnoreCase).Select(d => d.Id), send.Dependencies.Select(d => d.Id));
        Assert.Contains(new DependencyRef("encodeurl", "~1.0.2"), send.Dependencies);
    }

    [Fact]
    public void Packages_are_sorted_by_id_then_version_then_path()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Simple));

        List<(string Id, string Version, string Path)> actual = Packages(graph).Select(p => (p.Id, p.Version, p.Path!)).ToList();
        List<(string Id, string Version, string Path)> expected = actual
            .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Version, StringComparer.Ordinal)
            .ThenBy(p => p.Path, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(expected, actual);
        Assert.Equal(new[] { "2.0.0", "2.1.3" }, Packages(graph).Where(p => p.Id == "ms").Select(p => p.Version).ToArray());
    }

    [Fact]
    public void Workspace_links_and_first_party_members_are_not_packages()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Workspaces));

        Assert.Equal("sample-monorepo", graph.Name);
        Assert.Equal(5, Packages(graph).Count);
        Assert.DoesNotContain(Packages(graph), p => p.Id.StartsWith("@sample/", StringComparison.Ordinal));
        Assert.DoesNotContain(Packages(graph), p => p.Path!.StartsWith("packages/api", StringComparison.Ordinal));
    }

    [Fact]
    public void What_a_workspace_member_asks_for_makes_a_package_direct_in_that_member()
    {
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Workspaces));

        // The root asks for ms 2.1.3 (devDependency); member api asks for debug 4.3.4 (hoisted to the top level);
        // member web asks for debug 2.6.9, installed inside web.
        ResolvedPackage hoisted = At(graph, "node_modules/debug");
        Assert.True(hoisted.IsDirect);
        Assert.Equal("4.3.4", hoisted.Requested);

        ResolvedPackage inWeb = At(graph, "packages/web/node_modules/debug");
        Assert.True(inWeb.IsDirect);
        Assert.Equal("2.6.9", inWeb.Requested);   // web's own constraint, not api's

        Assert.True(At(graph, "node_modules/ms").IsDirect);
    }

    [Fact]
    public void An_optional_peer_dependency_is_not_something_the_project_asks_for()
    {
        // member web declares ms as an optional peer ("works with"); the ms inside web is only debug's dependency.
        ProjectGraph graph = Parse(NpmFixtures.Read(NpmFixtures.Workspaces));

        ResolvedPackage ms = At(graph, "packages/web/node_modules/ms");

        Assert.False(ms.IsDirect);
        Assert.Null(ms.Requested);
    }

    [Fact]
    public void Peer_dependencies_that_are_not_optional_count_as_requirements_of_an_installed_package()
    {
        string json = Lock(
            """ "dependencies": { "host": "1.0.0" } """,
            """
            "node_modules/host": { "version": "1.0.0", "peerDependencies": { "needed": ">=1", "wanted": "*" }, "peerDependenciesMeta": { "wanted": { "optional": true } }, "optionalDependencies": { "extra": "^2" }, "dependencies": { "plain": "~3.0.0" } }
            """);

        ResolvedPackage host = Packages(Parse(json)).Single();

        Assert.Equal(new[] { "extra", "needed", "plain" }, host.Dependencies.Select(d => d.Id).ToArray());
        Assert.Equal(">=1", host.Dependencies.Single(d => d.Id == "needed").Range);
    }

    [Fact]
    public void The_project_name_falls_back_to_the_given_name()
    {
        string json = """{ "lockfileVersion": 3, "packages": { "": { } } }""";

        Assert.Equal("my-dir", Parse(json, "my-dir").Name);
    }

    [Fact]
    public void Lockfile_version_2_is_read_from_the_packages_map_and_the_legacy_tree_is_ignored()
    {
        string json = """
        {
          "name": "demo", "lockfileVersion": 2, "requires": true,
          "packages": { "": { "dependencies": { "a": "^1.0.0" } }, "node_modules/a": { "version": "1.0.1" } },
          "dependencies": { "a": { "version": "1.0.1", "dependencies": { "b": { "version": "9.9.9" } } } }
        }
        """;

        ResolvedPackage only = Packages(Parse(json)).Single();

        Assert.Equal("a", only.Id);
        Assert.Equal("1.0.1", only.Version);
    }

    [Fact]
    public void Deeply_nested_legacy_trees_do_not_hit_the_json_depth_limit()
    {
        // lockfileVersion 2 repeats the tree below "dependencies", nesting two JSON levels per node_modules level.
        string nested = "{ \"version\": \"1.0.0\" }";

        for (int i = 0; i < 30; i++)
        {
            nested = $"{{ \"version\": \"1.0.0\", \"dependencies\": {{ \"x\": {nested} }} }}";
        }

        string json = $$"""{ "lockfileVersion": 2, "packages": { "": { } }, "dependencies": { "x": {{nested}} } }""";

        Assert.Empty(Packages(Parse(json)));
    }

    [Theory]
    [InlineData("""{ "name": "x", "version": "1.0.0" }""", "lockfileVersion")]
    [InlineData("""{ "lockfileVersion": "3", "packages": { "": {} } }""", "lockfileVersion")]
    [InlineData("""[]""", "lockfileVersion")]
    [InlineData("""{ "lockfileVersion": 1, "dependencies": {} }""", "npm 7")]
    [InlineData("""{ "lockfileVersion": 4, "packages": { "": {} } }""", "unsupported lockfileVersion 4")]
    [InlineData("""{ "lockfileVersion": 0, "packages": { "": {} } }""", "unsupported lockfileVersion 0")]
    [InlineData("""{ "lockfileVersion": 3 }""", "no 'packages' object")]
    [InlineData("""{ "lockfileVersion": 3, "packages": [] }""", "no 'packages' object")]
    [InlineData("""{ "lockfileVersion": 3, "packages": { "node_modules/a": { "version": "1.0.0" } } }""", "no root entry")]
    [InlineData("""{ "lockfileVersion": 3, "packages": { "": {}, "node_modules/a": "1.0.0" } }""", "not an object")]
    [InlineData("""{ "lockfileVersion": 3, "packages": { "": {}, "": {} } }""", "duplicate key")]
    [InlineData("{ nope", "not valid JSON")]
    public void A_file_that_is_not_a_supported_lock_file_is_rejected_with_the_reason(string json, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(json));

        Assert.Contains("package-lock.json", error.Message);
        Assert.Contains(expected, error.Message);
    }

    [Theory]
    [InlineData("""{ }""")]
    [InlineData("""{ "version": 1 }""")]
    [InlineData("""{ "version": "" }""")]
    [InlineData("""{ "version": "1.0.0\u001b[31m" }""")]
    public void An_installed_package_without_a_usable_version_is_rejected(string entry)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(Lock(string.Empty, $"\"node_modules/a\": {entry}")));

        Assert.Contains("'node_modules/a' has no valid 'version'", error.Message);
    }

    [Theory]
    [InlineData("node_modules/a b")]
    [InlineData("node_modules/a\\u001b[31m")]
    [InlineData("node_modules/")]
    [InlineData("node_modules/@scope")]
    [InlineData("node_modules/@scope/")]
    [InlineData("node_modules/@scope/a/b")]
    [InlineData("node_modules/..")]
    [InlineData("node_modules/a/../b")]
    [InlineData("node_modules/<script>")]
    [InlineData("node_modules/a;b")]
    [InlineData("foonode_modules/a")]
    public void A_key_that_npm_could_not_have_written_is_rejected_and_never_copied_raw(string key)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(
            () => Parse(Lock(string.Empty, $"\"{key}\": {{ \"version\": \"1.0.0\" }}")));

        Assert.Contains("package-lock.json", error.Message);
        Assert.False(error.Message.Contains('\u001b'));
    }

    [Theory]
    [InlineData("a")]
    [InlineData("@scope/pkg")]
    [InlineData("lodash.merge")]
    [InlineData("JSONStream")]
    [InlineData("a-b_c.d~e")]
    [InlineData("old!name(1)*'")]
    public void Valid_package_names_are_accepted(string name)
    {
        Assert.True(NpmLockParser.IsValidPackageName(name));
        Assert.Single(Packages(Parse(Lock(string.Empty, $"\"node_modules/{name}\": {{ \"version\": \"1.0.0\" }}"))));
    }

    [Fact]
    public void An_invalid_real_name_or_dependency_name_or_constraint_is_rejected()
    {
        Assert.Throws<InvalidInputException>(() => Parse(Lock(string.Empty, """ "node_modules/a": { "version": "1.0.0", "name": "bad name" } """)));
        Assert.Throws<InvalidInputException>(() => Parse(Lock(string.Empty, """ "node_modules/a": { "version": "1.0.0", "name": 5 } """)));
        Assert.Throws<InvalidInputException>(() => Parse(Lock(string.Empty, """ "node_modules/a": { "version": "1.0.0", "dependencies": { "x y": "1" } } """)));
        Assert.Throws<InvalidInputException>(() => Parse(Lock(string.Empty, """ "node_modules/a": { "version": "1.0.0", "dependencies": { "x": "1\u001b[2J" } } """)));
        Assert.Throws<InvalidInputException>(() => Parse(Lock(""" "dependencies": { "x y": "1" } """)));
        Assert.Throws<InvalidInputException>(() => Parse(Lock(string.Empty, $$"""  "node_modules/a": { "version": "1.0.0", "dependencies": { "x": "{{new string('1', 1001)}}" } } """)));
    }

    [Fact]
    public void A_non_string_constraint_becomes_an_empty_range_like_in_the_nuget_reader()
    {
        ResolvedPackage package = Packages(Parse(Lock(string.Empty, """ "node_modules/a": { "version": "1.0.0", "dependencies": { "x": 1 } } """))).Single();

        Assert.Equal(new DependencyRef("x", string.Empty), package.Dependencies.Single());
    }

    [Fact]
    public void Links_and_first_party_entries_are_skipped_even_if_they_look_like_packages()
    {
        string json = Lock(
            """ "dependencies": { "local": "file:../local" } """,
            """
            "node_modules/local": { "resolved": "../local", "link": true },
            "../local": { "name": "local", "version": "1.0.0" },
            "tools/cli": { "name": "cli", "version": "1.0.0", "dependencies": { "x": "^1" } },
            "node_modules/x": { "version": "1.2.3" }
            """);

        ResolvedPackage only = Packages(Parse(json)).Single();

        Assert.Equal("x", only.Id);
        Assert.True(only.IsDirect);   // asked for by the first-party member tools/cli
        Assert.Equal("^1", only.Requested);
    }

    [Fact]
    public void Package_names_are_not_taken_from_a_nested_path_segment_by_accident()
    {
        ProjectGraph graph = Parse(Lock(string.Empty, """ "node_modules/a": { "version": "1.0.0" }, "node_modules/a/node_modules/@s/b": { "version": "2.0.0" } """));

        ResolvedPackage scoped = At(graph, "node_modules/a/node_modules/@s/b");

        Assert.Equal("@s/b", scoped.Id);
        Assert.False(scoped.IsDirect);
    }
}

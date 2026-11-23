using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.NuGet;
using DepRisk.Core.Hypergraph;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>Real packages.lock.json files, written by dotnet restore (SDK 10.0.115) against a local feed of three demo packages.</summary>
internal static class NuGetLockFixtures
{
    /// <summary>Version 1: Demo.Logging direct; Demo.Util and Demo.Core transitive; a project reference named "shared".</summary>
    public const string V1 = """
{
  "version": 1,
  "dependencies": {
    "net10.0": {
      "Demo.Logging": {
        "type": "Direct",
        "requested": "[3.0.0, )",
        "resolved": "3.0.0",
        "contentHash": "9ZUQu4/yGLZTB89h8wH5yfQMXsaN66oH6jAlfzXM7SUsaZMD8V709JjVEBTdA60OVkxn+fAynVw43xZezLJL7g==",
        "dependencies": {
          "Demo.Core": "1.0.0",
          "Demo.Util": "[2.0.0, 3.0.0)"
        }
      },
      "Demo.Core": {
        "type": "Transitive",
        "resolved": "1.0.0",
        "contentHash": "aIMTyOHYa7sfThc10y2nPphT+vjcfdS/ylsxIdxX8kBfdaPDLSdVzPM12gS2OMqwW2P4qk0GW7O7wX53Kjovyw=="
      },
      "Demo.Util": {
        "type": "Transitive",
        "resolved": "2.1.0",
        "contentHash": "9qVLEG+LcuSgwrFF3j74bq0vgsf8F8v/KOKiWxYkvaaUAJtRyFBJebtavn55A4Ko+5zngxIiOg0yoCIfmsMwsg==",
        "dependencies": {
          "Demo.Core": "1.0.0"
        }
      },
      "shared": {
        "type": "Project",
        "dependencies": {
          "Demo.Util": "[2.1.0, )"
        }
      }
    }
  }
}
""";

    /// <summary>Version 2: central package management with transitive pinning; Demo.Core is CentralTransitive.</summary>
    public const string V2Central = """
{
  "version": 2,
  "dependencies": {
    "net10.0": {
      "Demo.Logging": {
        "type": "Direct",
        "requested": "[3.0.0, )",
        "resolved": "3.0.0",
        "contentHash": "9ZUQu4/yGLZTB89h8wH5yfQMXsaN66oH6jAlfzXM7SUsaZMD8V709JjVEBTdA60OVkxn+fAynVw43xZezLJL7g==",
        "dependencies": {
          "Demo.Core": "1.0.0",
          "Demo.Util": "[2.0.0, 3.0.0)"
        }
      },
      "Demo.Util": {
        "type": "Transitive",
        "resolved": "2.1.0",
        "contentHash": "9qVLEG+LcuSgwrFF3j74bq0vgsf8F8v/KOKiWxYkvaaUAJtRyFBJebtavn55A4Ko+5zngxIiOg0yoCIfmsMwsg==",
        "dependencies": {
          "Demo.Core": "1.0.0"
        }
      },
      "Demo.Core": {
        "type": "CentralTransitive",
        "requested": "[1.0.0, )",
        "resolved": "1.0.0",
        "contentHash": "aIMTyOHYa7sfThc10y2nPphT+vjcfdS/ylsxIdxX8kBfdaPDLSdVzPM12gS2OMqwW2P4qk0GW7O7wX53Kjovyw=="
      }
    }
  }
}
""";

    /// <summary>Version 3 as NuGet.Client reads it (targets at the top level, keyed by alias, each with a framework). Written by hand from the source: no SDK that writes it was available.</summary>
    public const string V3 = """
{
  "version": 3,
  "net10.0": {
    "framework": "net10.0",
    "dependencies": {
      "Demo.Logging": { "type": "Direct", "requested": "[3.0.0, )", "resolved": "3.0.0", "contentHash": "x", "dependencies": { "Demo.Core": "1.0.0" } },
      "Demo.Core": { "type": "Transitive", "resolved": "1.0.0", "contentHash": "y" }
    }
  },
  "net10.0/linux-x64": {
    "framework": "net10.0",
    "dependencies": {
      "Demo.Core": { "type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0", "contentHash": "y" }
    }
  },
  "note": { "text": "not a target: no framework" }
}
""";
}

public sealed class NuGetLockParserTests
{
    private static ProjectGraph Parse(string json) => NuGetLockParser.Parse(json, "App/packages.lock.json", "App");

    private static IReadOnlyList<ResolvedPackage> Packages(ProjectGraph graph, int target = 0) => graph.Targets[target].Packages;

    [Fact]
    public void A_real_version_1_file_gives_direct_and_transitive_packages_and_skips_the_project_reference()
    {
        ProjectGraph graph = Parse(NuGetLockFixtures.V1);

        TargetGraph target = Assert.Single(graph.Targets);
        Assert.Equal("net10.0", target.Name);
        Assert.Equal(["Demo.Core", "Demo.Logging", "Demo.Util"], target.Packages.Select(p => p.Id).ToArray());

        ResolvedPackage logging = target.Packages.Single(p => p.Id == "Demo.Logging");
        Assert.True(logging.IsDirect);
        Assert.Equal("3.0.0", logging.Version);
        Assert.Equal("[3.0.0, )", logging.Requested);
        Assert.Equal(["Demo.Core", "Demo.Util"], logging.Dependencies.Select(d => d.Id).ToArray());
        Assert.Equal("[2.0.0, 3.0.0)", logging.Dependencies.Single(d => d.Id == "Demo.Util").Range);

        ResolvedPackage util = target.Packages.Single(p => p.Id == "Demo.Util");
        Assert.False(util.IsDirect);
        Assert.Null(util.Requested);
        Assert.Null(util.Path);
        Assert.Equal("App", graph.Name);
        Assert.Equal("App/packages.lock.json", graph.AssetsFile);
    }

    [Fact]
    public void A_central_transitive_pin_is_installed_but_not_direct()
    {
        ProjectGraph graph = Parse(NuGetLockFixtures.V2Central);

        ResolvedPackage core = Packages(graph).Single(p => p.Id == "Demo.Core");
        Assert.False(core.IsDirect);
        Assert.Null(core.Requested);
        Assert.Equal("1.0.0", core.Version);
        Assert.True(Packages(graph).Single(p => p.Id == "Demo.Logging").IsDirect);
    }

    [Fact]
    public void Version_3_reads_targets_from_the_top_level_and_ignores_what_is_not_a_target()
    {
        ProjectGraph graph = Parse(NuGetLockFixtures.V3);

        Assert.Equal(["net10.0", "net10.0/linux-x64"], graph.Targets.Select(t => t.Name).ToArray());
        Assert.Equal(2, Packages(graph, 0).Count);
        Assert.True(Packages(graph, 1).Single().IsDirect);
    }

    [Fact]
    public void A_target_without_packages_is_allowed_but_a_file_without_targets_is_not()
    {
        ProjectGraph empty = Parse("""{ "version": 1, "dependencies": { "net10.0": {} } }""");
        Assert.Empty(Packages(empty));

        Assert.Contains("no targets", Assert.Throws<InvalidInputException>(() => Parse("""{ "version": 1, "dependencies": {} }""")).Message);
        Assert.Contains("no targets", Assert.Throws<InvalidInputException>(() => Parse("""{ "version": 3, "net10.0": { "dependencies": {} } }""")).Message);
    }

    [Fact]
    public void The_result_does_not_depend_on_the_order_in_the_file()
    {
        string a = """{ "version": 1, "dependencies": { "net9.0": { "B": { "type": "Transitive", "resolved": "1.0.0" }, "a": { "type": "Direct", "resolved": "2.0.0" } }, "net10.0": {} } }""";

        ProjectGraph graph = Parse(a);

        Assert.Equal(["net10.0", "net9.0"], graph.Targets.Select(t => t.Name).ToArray());
        Assert.Equal(["a", "B"], graph.Targets[1].Packages.Select(p => p.Id).ToArray());
    }

    [Theory]
    [InlineData("{ nope", "not valid JSON")]
    [InlineData("[]", "missing 'version'")]
    [InlineData("""{ "dependencies": {} }""", "missing 'version'")]
    [InlineData("""{ "version": "1", "dependencies": {} }""", "missing 'version'")]
    [InlineData("""{ "version": 4, "dependencies": {} }""", "unsupported packages lock file version 4")]
    [InlineData("""{ "version": 0, "dependencies": {} }""", "unsupported packages lock file version 0")]
    [InlineData("""{ "version": 1 }""", "no 'dependencies' object")]
    [InlineData("""{ "version": 2, "dependencies": [] }""", "no 'dependencies' object")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": [] } }""", "not an object")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": "1.0.0" } } }""", "not an object")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "resolved": "1.0.0" } } } }""", "no 'type'")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Sideways", "resolved": "1.0.0" } } } }""", "unknown type 'Sideways'")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Direct" } } } }""", "no valid 'resolved'")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Direct", "resolved": "" } } } }""", "no valid 'resolved'")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Direct", "resolved": "1.0.0" }, "a": { "type": "Direct", "resolved": "1.0.0" } } } }""", "duplicate package")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "../A": { "type": "Direct", "resolved": "1.0.0" } } } }""", "invalid package id")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Direct", "resolved": "1.0.0", "dependencies": { "B C": "1.0.0" } } } } }""", "invalid package id")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Direct", "resolved": "1.0.0", "dependencies": [] } } } }""", "is not an object")]
    [InlineData("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Direct", "resolved": "1.0.0", "dependencies": { "B": "1.0\n0" } } } } }""", "invalid version range")]
    [InlineData("""{ "version": 1, "dependencies": { "": {} } }""", "invalid target name")]
    [InlineData("""{ "version": 3, "net10.0": { "framework": "net10.0", "dependencies": [] } }""", "not an object")]
    public void A_file_that_cannot_be_read_with_confidence_is_rejected_with_the_reason(string json, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(json));

        Assert.Contains("App/packages.lock.json", error.Message);
        Assert.Contains(expected, error.Message);
    }

    [Fact]
    public void An_invalid_requested_range_is_dropped_not_copied()
    {
        ProjectGraph graph = Parse("""{ "version": 1, "dependencies": { "net10.0": { "A": { "type": "Direct", "requested": "bad\u0001", "resolved": "1.0.0" } } } }""");

        ResolvedPackage package = Packages(graph).Single();
        Assert.True(package.IsDirect);
        Assert.Null(package.Requested);
    }

    [Fact]
    public void A_nuget_hypergraph_can_be_built_from_a_lock_file()
    {
        ProjectGraph graph = Parse(NuGetLockFixtures.V1);

        TargetHypergraph hypergraph = HypergraphBuilder.BuildTarget(graph.Name, graph.Targets[0]);

        Assert.Equal(3, hypergraph.Nodes.Count);
        Hyperedge logging = hypergraph.Hyperedges.Single(e => e.Id == "Demo.Logging@3.0.0");
        Assert.All(logging.Requires, r => Assert.True(r.Satisfied));
    }
}

public sealed class NuGetLockScanTests : IDisposable
{
    private static readonly ToolInfo Tool = new("deprisk", "test");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-nuget-lock-" + Guid.NewGuid().ToString("N"));

    public NuGetLockScanTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string Put(string relative, string content)
    {
        string path = Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private const string Assets = """
        { "version": 3, "targets": { "net10.0": { "Demo.Core/1.0.0": { "type": "package" } } },
          "projectFileDependencyGroups": { "net10.0": [ "Demo.Core >= 1.0.0" ] },
          "project": { "restore": { "projectName": "App", "projectPath": "/x/App/App.csproj" } } }
        """;

    [Fact]
    public void A_lock_file_alone_is_scanned_and_named_after_the_project_file_beside_it()
    {
        Put("src/App/packages.lock.json", NuGetLockFixtures.V1);
        Put("src/App/App.csproj", "<Project />");

        ScanResult result = ScanService.Scan(_root, Tool);

        Assert.Equal("nuget", result.Ecosystem);
        ProjectGraph project = Assert.Single(result.Projects);
        Assert.Equal("App", project.Name);
        Assert.Equal("src/App/packages.lock.json", project.AssetsFile);
        Assert.Equal("src/App/App.csproj", project.ProjectFile);
        Assert.Equal(3, project.Targets[0].Packages.Count);
    }

    [Fact]
    public void Without_exactly_one_project_file_the_directory_names_the_project_and_no_project_file_is_claimed()
    {
        Put("lib/Core/packages.lock.json", NuGetLockFixtures.V1);
        Put("lib/Core/A.csproj", "<Project />");
        Put("lib/Core/B.csproj", "<Project />");
        Put("lib/Other/packages.lock.json", NuGetLockFixtures.V1);

        ScanResult result = ScanService.Scan(_root, Tool);

        Assert.Equal(["Core", "Other"], result.Projects.Select(p => p.Name).ToArray());
        Assert.All(result.Projects, p => Assert.Null(p.ProjectFile));
    }

    [Fact]
    public void A_project_with_an_assets_file_is_read_from_it_and_its_lock_file_is_not_read_again()
    {
        Put("App/App.csproj", "<Project />");
        Put("App/obj/project.assets.json", Assets);
        Put("App/packages.lock.json", NuGetLockFixtures.V1);

        ScanResult result = ScanService.Scan(_root, Tool);

        ProjectGraph project = Assert.Single(result.Projects);
        Assert.Equal("App/obj/project.assets.json", project.AssetsFile);
        Assert.Equal("App/App.csproj", project.ProjectFile);
    }

    [Fact]
    public void A_lock_file_is_read_when_the_assets_file_belongs_to_another_project()
    {
        Put("App/obj/project.assets.json", Assets);
        Put("Lib/packages.lock.json", NuGetLockFixtures.V1);

        ScanResult result = ScanService.Scan(_root, Tool);

        Assert.Equal(["App/obj/project.assets.json", "Lib/packages.lock.json"], result.Projects.Select(p => p.AssetsFile).ToArray());
    }

    [Fact]
    public void A_path_to_the_lock_file_and_the_ecosystem_option_both_work()
    {
        string file = Put("App/packages.lock.json", NuGetLockFixtures.V2Central);

        Assert.Equal("nuget", ScanService.Scan(file, Tool).Ecosystem);
        Assert.Equal("nuget", ScanService.Scan(_root, Tool, Ecosystem.NuGet).Ecosystem);
        Assert.Equal("App/packages.lock.json", ScanService.Scan(_root, Tool, Ecosystem.NuGet).Projects[0].AssetsFile);
    }

    [Fact]
    public void A_tree_with_a_lock_file_and_an_npm_lock_asks_for_a_choice_and_counts_the_kinds()
    {
        Put("App/packages.lock.json", NuGetLockFixtures.V1);
        Put("web/package-lock.json", """{ "lockfileVersion": 3, "packages": { "": {} } }""");

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool));

        Assert.Contains("NuGet (1 packages.lock.json)", error.Message);
        Assert.Contains("npm (1 package-lock.json)", error.Message);
    }

    [Fact]
    public void Nothing_found_mentions_both_nuget_files()
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool, Ecosystem.NuGet));

        Assert.Contains("project.assets.json", error.Message);
        Assert.Contains("packages.lock.json", error.Message);
    }

    [Fact]
    public void A_broken_lock_file_names_the_file()
    {
        Put("App/packages.lock.json", """{ "version": 9, "dependencies": {} }""");

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool));

        Assert.Contains("App/packages.lock.json", error.Message);
    }

    [Fact]
    public void The_same_input_gives_the_same_digest_and_a_changed_lock_file_changes_it()
    {
        string file = Put("App/packages.lock.json", NuGetLockFixtures.V1);

        string first = ScanService.ScanDetailed(_root, Tool).InputsDigest;
        Assert.Equal(first, ScanService.ScanDetailed(_root, Tool).InputsDigest);

        File.WriteAllText(file, NuGetLockFixtures.V2Central);
        Assert.NotEqual(first, ScanService.ScanDetailed(_root, Tool).InputsDigest);
    }
}

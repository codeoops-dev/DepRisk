using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.Hypergraph;
using DepRisk.Data.Sbom;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>SBOMs written by npm 10.9.9 (<c>npm sbom --sbom-format cyclonedx|spdx</c>) for a project with four packages; the lock file of the same project gives the same four.</summary>
internal static class SbomFixtures
{
    public const string NpmCycloneDx = """
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:e11994f8-52db-4517-abd0-6b572ccc421c",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-24T08:47:08.576Z",
    "lifecycles": [
      {
        "phase": "build"
      }
    ],
    "tools": [
      {
        "vendor": "npm",
        "name": "cli",
        "version": "10.9.9"
      }
    ],
    "component": {
      "bom-ref": "sbom-demo@1.0.0",
      "type": "library",
      "name": "sb",
      "version": "1.0.0",
      "scope": "required",
      "purl": "pkg:npm/sbom-demo@1.0.0",
      "properties": [
        {
          "name": "cdx:npm:package:path",
          "value": ""
        },
        {
          "name": "cdx:npm:package:private",
          "value": "true"
        }
      ],
      "externalReferences": []
    }
  },
  "components": [
    {
      "bom-ref": "@babel/helper-string-parser@7.25.9",
      "type": "library",
      "name": "@babel/helper-string-parser",
      "version": "7.25.9",
      "scope": "required",
      "author": "The Babel Team",
      "description": "A utility package to parse strings",
      "purl": "pkg:npm/%40babel/helper-string-parser@7.25.9",
      "properties": [
        {
          "name": "cdx:npm:package:path",
          "value": "node_modules/@babel/helper-string-parser"
        }
      ],
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.25.9.tgz"
        },
        {
          "type": "vcs",
          "url": "git+https://github.com/babel/babel.git"
        },
        {
          "type": "website",
          "url": "https://babel.dev/docs/en/next/babel-helper-string-parser"
        },
        {
          "type": "issue-tracker",
          "url": "https://github.com/babel/babel/issues"
        }
      ],
      "hashes": [
        {
          "alg": "SHA-512",
          "content": "e00fd20abff628b7798ebb4e305cda2a356d01e8b7fb6aff34286804da19dc4c8fffe1a58686841a858e6549859a82133fbcce2721c8326f8361177ca373ef1c"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    },
    {
      "bom-ref": "debug@2.6.9",
      "type": "library",
      "name": "debug",
      "version": "2.6.9",
      "scope": "required",
      "author": "TJ Holowaychuk",
      "description": "small debugging utility",
      "purl": "pkg:npm/debug@2.6.9",
      "properties": [
        {
          "name": "cdx:npm:package:path",
          "value": "node_modules/debug"
        }
      ],
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"
        },
        {
          "type": "vcs",
          "url": "git://github.com/visionmedia/debug.git"
        },
        {
          "type": "website",
          "url": "https://github.com/visionmedia/debug#readme"
        },
        {
          "type": "issue-tracker",
          "url": "https://github.com/visionmedia/debug/issues"
        }
      ],
      "hashes": [
        {
          "alg": "SHA-512",
          "content": "6c2ec496b7496899cf6c03fed44a2d62fa99b1bdde725e708ba05f8ba0494d470da30a7a72fb298348d7ce74532838e6fc4ec076014155e00f54c35c286b0730"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    },
    {
      "bom-ref": "left-pad@1.3.0",
      "type": "library",
      "name": "left-pad",
      "version": "1.3.0",
      "scope": "optional",
      "author": "azer",
      "description": "String left pad",
      "purl": "pkg:npm/left-pad@1.3.0",
      "properties": [
        {
          "name": "cdx:npm:package:path",
          "value": "node_modules/left-pad"
        },
        {
          "name": "cdx:npm:package:development",
          "value": "true"
        }
      ],
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
        },
        {
          "type": "vcs",
          "url": "git+ssh://git@github.com/stevemao/left-pad.git"
        },
        {
          "type": "website",
          "url": "https://github.com/stevemao/left-pad#readme"
        },
        {
          "type": "issue-tracker",
          "url": "https://github.com/stevemao/left-pad/issues"
        }
      ],
      "hashes": [
        {
          "alg": "SHA-512",
          "content": "5c8e4c3f354d0298c0ca1433a615fc06498ab0a5310f82ddc8adb88997901a29c137dc93413ddb165081cbf695c761eb35ca901ac768b7c821ae3cabbcc0a810"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "WTFPL"
          }
        }
      ]
    },
    {
      "bom-ref": "ms@2.0.0",
      "type": "library",
      "name": "ms",
      "version": "2.0.0",
      "scope": "required",
      "description": "Tiny milisecond conversion utility",
      "purl": "pkg:npm/ms@2.0.0",
      "properties": [
        {
          "name": "cdx:npm:package:path",
          "value": "node_modules/ms"
        }
      ],
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"
        },
        {
          "type": "vcs",
          "url": "git+https://github.com/zeit/ms.git"
        },
        {
          "type": "website",
          "url": "https://github.com/zeit/ms#readme"
        },
        {
          "type": "issue-tracker",
          "url": "https://github.com/zeit/ms/issues"
        }
      ],
      "hashes": [
        {
          "alg": "SHA-512",
          "content": "4e9a7ad0fe885090d3b8eabfe59f1c76c93326e8dfc2a7ce4e4af02308fb211212a679099d3e92c89e0f08f9c63281630bd75d85a979295218b40b7dee2c74e4"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "sbom-demo@1.0.0",
      "dependsOn": [
        "debug@2.6.9",
        "@babel/helper-string-parser@7.25.9",
        "left-pad@1.3.0"
      ]
    },
    {
      "ref": "@babel/helper-string-parser@7.25.9",
      "dependsOn": []
    },
    {
      "ref": "debug@2.6.9",
      "dependsOn": [
        "ms@2.0.0"
      ]
    },
    {
      "ref": "left-pad@1.3.0",
      "dependsOn": []
    },
    {
      "ref": "ms@2.0.0",
      "dependsOn": []
    }
  ]
}
""";

    public const string NpmSpdx = """
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "sbom-demo@1.0.0",
  "documentNamespace": "http://spdx.org/spdxdocs/sbom-demo-1.0.0-002c876b-1827-46db-92ca-e6bbc2594c18",
  "creationInfo": {
    "created": "2026-11-24T08:47:08.894Z",
    "creators": [
      "Tool: npm/cli-10.9.9"
    ]
  },
  "documentDescribes": [
    "SPDXRef-Package-sbom-demo-1.0.0"
  ],
  "packages": [
    {
      "name": "sbom-demo",
      "SPDXID": "SPDXRef-Package-sbom-demo-1.0.0",
      "versionInfo": "1.0.0",
      "packageFileName": "",
      "primaryPackagePurpose": "LIBRARY",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "homepage": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/sbom-demo@1.0.0"
        }
      ]
    },
    {
      "name": "@babel/helper-string-parser",
      "SPDXID": "SPDXRef-Package-babel.helper-string-parser-7.25.9",
      "versionInfo": "7.25.9",
      "packageFileName": "node_modules/@babel/helper-string-parser",
      "description": "A utility package to parse strings",
      "downloadLocation": "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.25.9.tgz",
      "filesAnalyzed": false,
      "homepage": "https://babel.dev/docs/en/next/babel-helper-string-parser",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/%40babel/helper-string-parser@7.25.9"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA512",
          "checksumValue": "e00fd20abff628b7798ebb4e305cda2a356d01e8b7fb6aff34286804da19dc4c8fffe1a58686841a858e6549859a82133fbcce2721c8326f8361177ca373ef1c"
        }
      ]
    },
    {
      "name": "debug",
      "SPDXID": "SPDXRef-Package-debug-2.6.9",
      "versionInfo": "2.6.9",
      "packageFileName": "node_modules/debug",
      "description": "small debugging utility",
      "downloadLocation": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
      "filesAnalyzed": false,
      "homepage": "https://github.com/visionmedia/debug#readme",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/debug@2.6.9"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA512",
          "checksumValue": "6c2ec496b7496899cf6c03fed44a2d62fa99b1bdde725e708ba05f8ba0494d470da30a7a72fb298348d7ce74532838e6fc4ec076014155e00f54c35c286b0730"
        }
      ]
    },
    {
      "name": "left-pad",
      "SPDXID": "SPDXRef-Package-left-pad-1.3.0",
      "versionInfo": "1.3.0",
      "packageFileName": "node_modules/left-pad",
      "description": "String left pad",
      "downloadLocation": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "filesAnalyzed": false,
      "homepage": "https://github.com/stevemao/left-pad#readme",
      "licenseDeclared": "WTFPL",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/left-pad@1.3.0"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA512",
          "checksumValue": "5c8e4c3f354d0298c0ca1433a615fc06498ab0a5310f82ddc8adb88997901a29c137dc93413ddb165081cbf695c761eb35ca901ac768b7c821ae3cabbcc0a810"
        }
      ]
    },
    {
      "name": "ms",
      "SPDXID": "SPDXRef-Package-ms-2.0.0",
      "versionInfo": "2.0.0",
      "packageFileName": "node_modules/ms",
      "description": "Tiny milisecond conversion utility",
      "downloadLocation": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
      "filesAnalyzed": false,
      "homepage": "https://github.com/zeit/ms#readme",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/ms@2.0.0"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA512",
          "checksumValue": "4e9a7ad0fe885090d3b8eabfe59f1c76c93326e8dfc2a7ce4e4af02308fb211212a679099d3e92c89e0f08f9c63281630bd75d85a979295218b40b7dee2c74e4"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-sbom-demo-1.0.0",
      "relationshipType": "DESCRIBES"
    },
    {
      "spdxElementId": "SPDXRef-Package-debug-2.6.9",
      "relatedSpdxElement": "SPDXRef-Package-sbom-demo-1.0.0",
      "relationshipType": "DEPENDENCY_OF"
    },
    {
      "spdxElementId": "SPDXRef-Package-babel.helper-string-parser-7.25.9",
      "relatedSpdxElement": "SPDXRef-Package-sbom-demo-1.0.0",
      "relationshipType": "DEPENDENCY_OF"
    },
    {
      "spdxElementId": "SPDXRef-Package-left-pad-1.3.0",
      "relatedSpdxElement": "SPDXRef-Package-sbom-demo-1.0.0",
      "relationshipType": "DEV_DEPENDENCY_OF"
    },
    {
      "spdxElementId": "SPDXRef-Package-ms-2.0.0",
      "relatedSpdxElement": "SPDXRef-Package-debug-2.6.9",
      "relationshipType": "DEPENDENCY_OF"
    }
  ]
}
""";

    /// <summary>Hand-written in the shape cyclonedx-dotnet writes (no such tool was available): a NuGet project with a package that has a dependency.</summary>
    public const string NuGetCycloneDx = """
        { "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
          "metadata": { "component": { "type": "application", "bom-ref": "App", "name": "App", "version": "1.0.0" } },
          "components": [
            { "type": "library", "bom-ref": "pkg:nuget/Newtonsoft.Json@13.0.1", "name": "Newtonsoft.Json", "version": "13.0.1", "purl": "pkg:nuget/Newtonsoft.Json@13.0.1" },
            { "type": "library", "bom-ref": "pkg:nuget/Demo.Logging@3.0.0", "name": "Demo.Logging", "version": "3.0.0", "purl": "pkg:nuget/Demo.Logging@3.0.0" },
            { "type": "library", "bom-ref": "pkg:nuget/Demo.Core@1.0.0", "name": "Demo.Core", "version": "1.0.0", "purl": "pkg:nuget/Demo.Core@1.0.0" } ],
          "dependencies": [
            { "ref": "App", "dependsOn": [ "pkg:nuget/Newtonsoft.Json@13.0.1", "pkg:nuget/Demo.Logging@3.0.0" ] },
            { "ref": "pkg:nuget/Demo.Logging@3.0.0", "dependsOn": [ "pkg:nuget/Demo.Core@1.0.0" ] },
            { "ref": "pkg:nuget/Newtonsoft.Json@13.0.1", "dependsOn": [] },
            { "ref": "pkg:nuget/Demo.Core@1.0.0", "dependsOn": [] } ] }
        """;
}

public sealed class SbomParserTests
{
    private static (Ecosystem Ecosystem, ProjectGraph Graph) Parse(string json, Ecosystem? requested = null) =>
        SbomParser.Parse(json, "bom.json", "bom", requested);

    private static IReadOnlyList<ResolvedPackage> Packages(ProjectGraph graph) => Assert.Single(graph.Targets).Packages;

    [Fact]
    public void A_cyclonedx_file_written_by_npm_gives_the_packages_the_lock_file_gives()
    {
        (Ecosystem ecosystem, ProjectGraph graph) = Parse(SbomFixtures.NpmCycloneDx);

        Assert.Equal(Ecosystem.Npm, ecosystem);
        Assert.Equal("sbom", Assert.Single(graph.Targets).Name);
        Assert.Equal(
            ["@babel/helper-string-parser 7.25.9 direct", "debug 2.6.9 direct", "left-pad 1.3.0 direct", "ms 2.0.0 transitive"],
            Packages(graph).Select(p => $"{p.Id} {p.Version} {(p.IsDirect ? "direct" : "transitive")}").ToArray());
        Assert.Equal(["ms"], Packages(graph).Single(p => p.Id == "debug").Dependencies.Select(d => d.Id).ToArray());
        Assert.All(Packages(graph), p => Assert.Null(p.Path));
        Assert.All(Packages(graph), p => Assert.Null(p.Requested));
        Assert.DoesNotContain(Packages(graph), p => p.Id == "sbom-demo");   // the root is the project, not a dependency
    }

    [Fact]
    public void An_spdx_file_written_by_npm_gives_the_same_including_dev_dependencies()
    {
        (Ecosystem ecosystem, ProjectGraph graph) = Parse(SbomFixtures.NpmSpdx);

        Assert.Equal(Ecosystem.Npm, ecosystem);
        Assert.Equal("sbom-demo@1.0.0", graph.Name);
        Assert.Equal(
            ["@babel/helper-string-parser 7.25.9 direct", "debug 2.6.9 direct", "left-pad 1.3.0 direct", "ms 2.0.0 transitive"],
            Packages(graph).Select(p => $"{p.Id} {p.Version} {(p.IsDirect ? "direct" : "transitive")}").ToArray());
        Assert.Equal(["ms"], Packages(graph).Single(p => p.Id == "debug").Dependencies.Select(d => d.Id).ToArray());
    }

    [Fact]
    public void A_nuget_sbom_keeps_the_case_of_the_id()
    {
        (Ecosystem ecosystem, ProjectGraph graph) = Parse(SbomFixtures.NuGetCycloneDx);

        Assert.Equal(Ecosystem.NuGet, ecosystem);
        Assert.Equal("App", graph.Name);
        Assert.Equal(["Demo.Core", "Demo.Logging", "Newtonsoft.Json"], Packages(graph).Select(p => p.Id).ToArray());
        Assert.False(Packages(graph).Single(p => p.Id == "Demo.Core").IsDirect);
        Assert.True(Packages(graph).Single(p => p.Id == "Demo.Logging").IsDirect);
        Assert.Equal("Demo.Core", Packages(graph).Single(p => p.Id == "Demo.Logging").Dependencies.Single().Id);
    }

    private static string CycloneDx(string components, string dependencies = """[ { "ref": "root", "dependsOn": [ "a" ] }, { "ref": "a", "dependsOn": [] } ]""", string spec = "1.5") =>
        $$"""
        { "bomFormat": "CycloneDX", "specVersion": "{{spec}}", "metadata": { "component": { "bom-ref": "root", "name": "demo", "purl": "pkg:npm/demo@1.0.0" } },
          "components": {{components}}, "dependencies": {{dependencies}} }
        """;

    [Fact]
    public void Components_of_other_ecosystems_and_without_a_purl_are_not_read()
    {
        string json = CycloneDx("""
            [ { "bom-ref": "a", "name": "a", "purl": "pkg:npm/a@1.0.0" },
              { "bom-ref": "m", "name": "m", "purl": "pkg:maven/org.x/m@1.0.0" },
              { "bom-ref": "p", "name": "p", "purl": "pkg:pypi/p@1.0.0" },
              { "bom-ref": "n", "name": "n", "version": "1.0.0" } ]
            """);

        (Ecosystem ecosystem, ProjectGraph graph) = Parse(json);

        Assert.Equal(Ecosystem.Npm, ecosystem);
        Assert.Equal("a", Assert.Single(Packages(graph)).Id);
    }

    [Fact]
    public void Both_ecosystems_ask_for_a_choice_and_the_choice_picks_one()
    {
        string json = CycloneDx("""
            [ { "bom-ref": "a", "name": "a", "purl": "pkg:npm/a@1.0.0" },
              { "bom-ref": "n", "name": "n", "purl": "pkg:nuget/N@2.0.0" } ]
            """, """[ { "ref": "root", "dependsOn": [ "a", "n" ] } ]""");

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(json));
        Assert.Contains("both NuGet and npm", error.Message);
        Assert.Contains("--ecosystem", error.Message);

        Assert.Equal("a", Packages(Parse(json, Ecosystem.Npm).Graph).Single().Id);
        Assert.Equal("N", Packages(Parse(json, Ecosystem.NuGet).Graph).Single().Id);
    }

    [Fact]
    public void A_named_ecosystem_the_sbom_does_not_have_is_an_error()
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(SbomFixtures.NpmCycloneDx, Ecosystem.NuGet));

        Assert.Contains("no NuGet components", error.Message);
    }

    [Fact]
    public void An_sbom_without_components_of_either_ecosystem_is_an_error()
    {
        string json = CycloneDx("""[ { "bom-ref": "m", "purl": "pkg:maven/org.x/m@1.0.0" } ]""");

        Assert.Contains("no NuGet or npm components", Assert.Throws<InvalidInputException>(() => Parse(json)).Message);
    }

    [Fact]
    public void Nested_components_are_read_and_a_component_under_several_parents_is_one_package()
    {
        string json = CycloneDx("""
            [ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0", "components": [ { "bom-ref": "b1", "purl": "pkg:npm/b@2.0.0" } ] },
              { "bom-ref": "b2", "purl": "pkg:npm/b@2.0.0" },
              { "bom-ref": "b3", "purl": "pkg:npm/b@3.0.0" } ]
            """, """[ { "ref": "root", "dependsOn": [ "a", "b2" ] }, { "ref": "a", "dependsOn": [ "b1" ] } ]""");

        ProjectGraph graph = Parse(json).Graph;

        Assert.Equal(["a 1.0.0", "b 2.0.0", "b 3.0.0"], Packages(graph).Select(p => $"{p.Id} {p.Version}").ToArray());
        Assert.True(Packages(graph).Single(p => p.Id == "b" && p.Version == "2.0.0").IsDirect);   // direct through b2, transitive through a
        Assert.False(Packages(graph).Single(p => p.Id == "b" && p.Version == "3.0.0").IsDirect);
        Assert.Equal("b", Packages(graph).Single(p => p.Id == "a").Dependencies.Single().Id);
    }

    [Theory]
    [InlineData("pkg:npm/%40scope/name@1.2.3", "@scope/name", "1.2.3")]
    [InlineData("pkg:npm/@scope/name@1.2.3", "@scope/name", "1.2.3")]
    [InlineData("PKG:NPM/name@1.2.3", "name", "1.2.3")]
    [InlineData("pkg://npm/name@1.2.3", "name", "1.2.3")]
    [InlineData("pkg:npm/name@1.2.3?repository_url=https%3A%2F%2Fu%3ATOKEN123%40h%2Fx#sub/path", "name", "1.2.3")]
    [InlineData("pkg:npm/name@1.2.3+build.5", "name", "1.2.3+build.5")]
    [InlineData("pkg:npm/%40scope/name", "@scope/name", SbomParser.UnknownVersion)]
    [InlineData("pkg:npm/name", "name", SbomParser.UnknownVersion)]
    public void Package_urls_are_read_by_the_rules_of_the_purl_specification(string purl, string id, string version)
    {
        string json = CycloneDx($$"""[ { "bom-ref": "a", "purl": "{{purl}}" } ]""", """[ { "ref": "root", "dependsOn": [ "a" ] } ]""");

        ResolvedPackage package = Packages(Parse(json).Graph).Single();

        Assert.Equal(id, package.Id);
        Assert.Equal(version, package.Version);
        Assert.DoesNotContain("TOKEN123", package.Id + package.Version);
    }

    [Fact]
    public void The_version_field_is_used_only_when_the_purl_has_none_and_the_purl_wins_otherwise()
    {
        string json = CycloneDx("""
            [ { "bom-ref": "a", "version": "9.9.9", "purl": "pkg:npm/a@1.0.0" },
              { "bom-ref": "b", "version": "2.0.0", "purl": "pkg:npm/b" } ]
            """, """[ { "ref": "root", "dependsOn": [ "a", "b" ] } ]""");

        ProjectGraph graph = Parse(json).Graph;

        Assert.Equal("1.0.0", Packages(graph).Single(p => p.Id == "a").Version);
        Assert.Equal("2.0.0", Packages(graph).Single(p => p.Id == "b").Version);
    }

    [Theory]
    [InlineData("{ nope", "not valid JSON")]
    [InlineData("[]", "not a CycloneDX or SPDX JSON document")]
    [InlineData("""{ "name": "x" }""", "no 'bomFormat' and no 'spdxVersion'")]
    [InlineData("""{ "bomFormat": "Other", "specVersion": "1.5" }""", "unsupported 'bomFormat'")]
    [InlineData("""{ "bomFormat": "CycloneDX" }""", "unsupported CycloneDX specVersion '(none)'")]
    [InlineData("""{ "bomFormat": "CycloneDX", "specVersion": "1.1" }""", "unsupported CycloneDX specVersion '1.1'")]
    [InlineData("""{ "bomFormat": "CycloneDX", "specVersion": "2.0" }""", "unsupported CycloneDX specVersion '2.0'")]
    [InlineData("""{ "spdxVersion": "SPDX-3.0.1" }""", "unsupported SPDX version 'SPDX-3.0.1'")]
    [InlineData("""{ "spdxVersion": "SPDX-2.1" }""", "unsupported SPDX version 'SPDX-2.1'")]
    public void A_file_that_is_not_a_supported_sbom_is_rejected_with_the_reason(string json, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(json));

        Assert.Contains("bom.json", error.Message);
        Assert.Contains(expected, error.Message);
    }

    [Theory]
    [InlineData("""[ { "bom-ref": "a", "purl": "not a purl" } ]""", "is not a package URL")]
    [InlineData("""[ { "bom-ref": "a", "purl": "pkg:npm/" } ]""", "is not a package URL")]
    [InlineData("""[ { "bom-ref": "a", "purl": "pkg:npm/bad%20name@1.0.0" } ]""", "invalid npm package name")]
    [InlineData("""[ { "bom-ref": "a", "purl": "pkg:npm/scope/name@1.0.0" } ]""", "invalid npm package name")]
    [InlineData("""[ { "bom-ref": "a", "purl": "pkg:nuget/org/Id@1.0.0" } ]""", "invalid NuGet package name")]
    [InlineData("""[ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0%0A2" } ]""", "invalid version")]
    public void A_purl_that_cannot_be_a_package_the_manager_wrote_is_rejected(string components, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(CycloneDx(components)));

        Assert.Contains(expected, error.Message);
    }

    [Fact]
    public void A_flat_list_without_relationships_is_refused_because_direct_cannot_be_known()
    {
        string noDependencies = """
            { "bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": { "component": { "bom-ref": "root", "name": "demo" } },
              "components": [ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0" } ] }
            """;
        string emptyDependsOn = CycloneDx("""[ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0" } ]""", """[ { "ref": "root", "dependsOn": [] }, { "ref": "a", "dependsOn": [] } ]""");

        foreach (string json in new[] { noDependencies, emptyDependsOn })
        {
            InvalidInputException error = Assert.Throws<InvalidInputException>(() => Parse(json));
            Assert.Contains("records no dependency relationships", error.Message);
        }
    }

    [Fact]
    public void An_sbom_whose_root_has_no_entry_or_is_not_named_is_refused()
    {
        string noRootEntry = CycloneDx("""[ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0" }, { "bom-ref": "b", "purl": "pkg:npm/b@1.0.0" } ]""", """[ { "ref": "a", "dependsOn": [ "b" ] } ]""");
        string noRoot = """
            { "bomFormat": "CycloneDX", "specVersion": "1.5",
              "components": [ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0" }, { "bom-ref": "b", "purl": "pkg:npm/b@1.0.0" } ],
              "dependencies": [ { "ref": "a", "dependsOn": [ "b" ] } ] }
            """;

        Assert.Contains("records no dependency relationships", Assert.Throws<InvalidInputException>(() => Parse(noRootEntry)).Message);
        Assert.Contains("does not say which component is the project", Assert.Throws<InvalidInputException>(() => Parse(noRoot)).Message);
    }

    [Fact]
    public void An_spdx_document_needs_something_it_describes_and_relationships_from_it()
    {
        string noDescribes = SbomFixtures.NpmSpdx
            .Replace("\"documentDescribes\"", "\"x-documentDescribes\"", StringComparison.Ordinal)
            .Replace("\"DESCRIBES\"", "\"CONTAINS\"", StringComparison.Ordinal);

        Assert.Contains("does not say which component is the project", Assert.Throws<InvalidInputException>(() => Parse(noDescribes)).Message);
    }

    [Fact]
    public void Spdx_relationship_directions_are_read_both_ways()
    {
        string json = """
            { "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "demo", "documentDescribes": [ "SPDXRef-root" ],
              "packages": [
                { "SPDXID": "SPDXRef-root", "name": "demo", "externalRefs": [ { "referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:nuget/Demo@1.0.0" } ] },
                { "SPDXID": "SPDXRef-a", "name": "A", "externalRefs": [ { "referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:nuget/A@1.0.0" } ] },
                { "SPDXID": "SPDXRef-b", "name": "B", "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:nuget/B@2.0.0" } ] },
                { "SPDXID": "SPDXRef-c", "name": "C", "externalRefs": [ { "referenceCategory": "SECURITY", "referenceType": "purl", "referenceLocator": "pkg:nuget/C@3.0.0" } ] },
                { "SPDXID": "SPDXRef-d", "name": "D", "externalRefs": [ { "referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:nuget/D@4.0.0" } ] } ],
              "relationships": [
                { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root" },
                { "spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-a" },
                { "spdxElementId": "SPDXRef-b", "relationshipType": "RUNTIME_DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-a" },
                { "spdxElementId": "SPDXRef-d", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-a" } ] }
            """;

        ProjectGraph graph = Parse(json).Graph;

        // C has a purl in a category that is not PACKAGE-MANAGER, so it is not read; D is only contained, not depended on.
        Assert.Equal(["A 1.0.0 direct", "B 2.0.0 transitive", "D 4.0.0 transitive"], Packages(graph).Select(p => $"{p.Id} {p.Version} {(p.IsDirect ? "direct" : "transitive")}").ToArray());
        Assert.Equal("B", Packages(graph).Single(p => p.Id == "A").Dependencies.Single().Id);
    }

    [Fact]
    public void The_result_does_not_depend_on_the_order_in_the_file()
    {
        string a = CycloneDx("""[ { "bom-ref": "z", "purl": "pkg:npm/z@1.0.0" }, { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0" } ]""", """[ { "ref": "root", "dependsOn": [ "z", "a" ] } ]""");
        string b = CycloneDx("""[ { "bom-ref": "a", "purl": "pkg:npm/a@1.0.0" }, { "bom-ref": "z", "purl": "pkg:npm/z@1.0.0" } ]""", """[ { "ref": "root", "dependsOn": [ "a", "z" ] } ]""");

        Assert.Equal(Packages(Parse(a).Graph).Select(p => p.Id).ToArray(), Packages(Parse(b).Graph).Select(p => p.Id).ToArray());
        Assert.Equal(["a", "z"], Packages(Parse(a).Graph).Select(p => p.Id).ToArray());
    }

    [Theory]
    [InlineData("bom.json", true)]
    [InlineData("SBOM.JSON", true)]
    [InlineData("app.cdx.json", true)]
    [InlineData("app.spdx.json", true)]
    [InlineData("package-lock.json", false)]
    [InlineData("packages.lock.json", false)]
    [InlineData("project.assets.json", false)]
    [InlineData("app.json", false)]
    public void The_file_names_read_as_an_sbom_without_being_asked(string name, bool expected)
    {
        Assert.Equal(expected, SbomParser.IsSbomFileName(name));
    }

    [Fact]
    public void An_sbom_is_recognized_by_its_content_and_never_throws_for_anything_else()
    {
        Assert.True(SbomParser.LooksLikeSbom(SbomFixtures.NpmCycloneDx));
        Assert.True(SbomParser.LooksLikeSbom(SbomFixtures.NpmSpdx));
        Assert.False(SbomParser.LooksLikeSbom("""{ "lockfileVersion": 3, "packages": {} }"""));
        Assert.False(SbomParser.LooksLikeSbom("[]"));
        Assert.False(SbomParser.LooksLikeSbom("{ nope"));
        Assert.False(SbomParser.LooksLikeSbom(string.Empty));
    }
}

public sealed class SbomScanTests : IDisposable
{
    private static readonly ToolInfo Tool = new("deprisk", "test");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-sbom-" + Guid.NewGuid().ToString("N"));

    public SbomScanTests() => Directory.CreateDirectory(_root);

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

    [Theory]
    [InlineData("bom.json")]
    [InlineData("sbom.json")]
    [InlineData("app.cdx.json")]
    [InlineData("app.spdx.json")]
    public void A_file_with_an_sbom_name_is_scanned_and_the_graph_is_marked_as_coming_from_an_sbom(string name)
    {
        string file = Put("out/" + name, name.Contains("spdx", StringComparison.Ordinal) ? SbomFixtures.NpmSpdx : SbomFixtures.NpmCycloneDx);

        ScanOutcome outcome = ScanService.ScanDetailed(file, Tool);

        Assert.True(outcome.IsSbom);
        Assert.Equal("npm", outcome.Result.Ecosystem);
        ProjectGraph project = Assert.Single(outcome.Result.Projects);
        Assert.Equal(name, project.AssetsFile);
        Assert.Null(project.ProjectFile);
        Assert.Equal(4, project.Targets[0].Packages.Count);
    }

    [Fact]
    public void A_file_with_another_name_is_read_as_an_sbom_when_the_ecosystem_is_named_and_the_content_is_one()
    {
        string file = Put("out/inventory.json", SbomFixtures.NpmCycloneDx);

        Assert.True(ScanService.ScanDetailed(file, Tool, Ecosystem.Npm).IsSbom);

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(file, Tool));
        Assert.Contains("is not a dependency file", error.Message);
        Assert.Contains("*.cdx.json", error.Message);
    }

    [Fact]
    public void A_lock_file_is_not_taken_for_an_sbom_when_the_ecosystem_is_named()
    {
        string file = Put("web/package-lock.json", """{ "lockfileVersion": 3, "packages": { "": {}, "node_modules/a": { "version": "1.0.0" } } }""");

        ScanOutcome outcome = ScanService.ScanDetailed(file, Tool, Ecosystem.Npm);

        Assert.False(outcome.IsSbom);
        Assert.Equal("web/package-lock.json".Split('/')[1], Assert.Single(outcome.Result.Projects).AssetsFile);
    }

    [Fact]
    public void A_directory_scan_does_not_find_an_sbom_so_one_is_not_counted_with_the_lock_file_it_came_from()
    {
        Put("web/package-lock.json", """{ "lockfileVersion": 3, "packages": { "": {}, "node_modules/a": { "version": "1.0.0" } } }""");
        Put("web/bom.json", SbomFixtures.NpmCycloneDx);
        Put("docs/sample.cdx.json", SbomFixtures.NpmSpdx);

        ScanResult result = ScanService.Scan(_root, Tool);

        ProjectGraph project = Assert.Single(result.Projects);
        Assert.Equal("web/package-lock.json", project.AssetsFile);
    }

    [Fact]
    public void A_directory_with_only_an_sbom_says_that_an_sbom_is_read_only_when_named()
    {
        Put("bom.json", SbomFixtures.NpmCycloneDx);

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(_root, Tool));

        Assert.Contains("SBOM is read only when its path is given", error.Message);
    }

    [Fact]
    public void The_digest_covers_the_sbom_and_changes_with_it()
    {
        string file = Put("bom.json", SbomFixtures.NpmCycloneDx);

        string first = ScanService.ScanDetailed(file, Tool).InputsDigest;
        Assert.Equal(first, ScanService.ScanDetailed(file, Tool).InputsDigest);

        File.WriteAllText(file, SbomFixtures.NpmCycloneDx.Replace("2.6.9", "2.6.8", StringComparison.Ordinal));
        Assert.NotEqual(first, ScanService.ScanDetailed(file, Tool).InputsDigest);
    }

    [Fact]
    public void A_broken_sbom_names_the_file()
    {
        string file = Put("out/bom.json", """{ "bomFormat": "CycloneDX", "specVersion": "9.9" }""");

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => ScanService.Scan(file, Tool));

        Assert.Contains("bom.json", error.Message);
        Assert.Contains("specVersion '9.9'", error.Message);
    }

    [Fact]
    public void The_graph_command_refuses_an_sbom_because_it_has_no_ranges_and_no_install_paths()
    {
        string file = Put("bom.json", SbomFixtures.NpmCycloneDx);

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => HypergraphService.Build(file, Tool));

        Assert.Contains("an SBOM records neither", error.Message);
    }
}

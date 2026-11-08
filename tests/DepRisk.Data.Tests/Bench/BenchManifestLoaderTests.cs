using System.Text;
using DepRisk.Core;
using DepRisk.Data.Bench;
using Xunit;

namespace DepRisk.Data.Tests.Bench;

public sealed class BenchManifestLoaderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-bench-manifest-" + Guid.NewGuid().ToString("N"));

    public BenchManifestLoaderTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "proj"));
        Directory.CreateDirectory(Path.Combine(_root, "osv"));
        Directory.CreateDirectory(Path.Combine(_root, "symbols"));
        File.WriteAllText(Path.Combine(_root, "symbols", "s.json"), "{}");
        File.WriteAllText(Path.Combine(_root, "outside.txt"), "x");
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private const string Label = """{ "advisory": "GHSA-1", "package": "Pkg", "exploited": true, "reachable": null }""";

    private static string CaseJson(string? id = "c1", string? split = "dev", string path = "proj", string extra = "", string labels = Label) =>
        $$"""
        { "id": "{{id}}", "split": "{{split}}", "path": "{{path}}", "advisories": "osv"{{extra}}, "labels": [ {{labels}} ] }
        """;

    private string Write(string cases = "", string top = "", string asOf = "2026-01-31", string from = "2026-02-01", string to = "2026-07-31", string file = "m.json")
    {
        string json = $$"""
            {
              "schemaVersion": 1, "name": "t", "description": "d", "synthetic": true,
              "signalsAsOf": "{{asOf}}", "outcomeWindow": { "from": "{{from}}", "to": "{{to}}" },
              "labelSource": "test"{{top}},
              "cases": [ {{(cases.Length == 0 ? CaseJson() : cases)}} ]
            }
            """;
        string path = Path.Combine(_root, file);
        File.WriteAllText(path, json, new UTF8Encoding(false));
        return path;
    }

    private string WriteRaw(string json)
    {
        string path = Path.Combine(_root, "raw.json");
        File.WriteAllText(path, json, new UTF8Encoding(false));
        return path;
    }

    private static void Refused(string path, string expectedPart)
    {
        InvalidInputException ex = Assert.Throws<InvalidInputException>(() => BenchManifestLoader.Load(path));
        Assert.Contains(expectedPart, ex.Message);
    }

    [Fact]
    public void A_valid_manifest_loads_with_absolute_paths_inside_its_directory_and_a_digest_of_its_bytes()
    {
        string path = Write(CaseJson(extra: """, "epss": "symbols/s.json", "symbols": "symbols/s.json", "source": "proj", "ecosystem": "nuget", "entrypoints": "public-api", "entrypointNames": ["A.B.C"]"""));
        LoadedBenchManifest loaded = BenchManifestLoader.Load(path);

        Assert.Equal(Digest.Sha256Hex(File.ReadAllBytes(path)), loaded.Digest);
        Assert.Equal(_root, loaded.Root);
        Assert.True(loaded.Manifest.Synthetic);
        Assert.Equal(new DateOnly(2026, 1, 31), loaded.Manifest.SignalsAsOf);
        Assert.Equal(new DateOnly(2026, 2, 1), loaded.Manifest.OutcomeFrom);

        BenchCase c = Assert.Single(loaded.Manifest.Cases);
        Assert.Equal(Path.Combine(_root, "proj"), c.ScanPath);
        Assert.Equal(Path.Combine(_root, "osv"), c.AdvisoriesPath);
        Assert.Equal(Path.Combine(_root, "symbols", "s.json"), c.SymbolsPath);
        Assert.Equal(Ecosystem.NuGet, c.Ecosystem);
        Assert.Equal("public-api", c.EntrypointMode);
        Assert.Equal(new[] { "A.B.C" }, c.Entrypoints.ToArray());
        Assert.Null(c.KevPath);

        BenchLabel label = Assert.Single(c.Labels);
        Assert.True(label.Exploited);
        Assert.Null(label.Reachable);
    }

    [Fact]
    public void Defaults_are_auto_entrypoints_no_ecosystem_and_no_optional_data()
    {
        BenchCase c = BenchManifestLoader.Load(Write()).Manifest.Cases[0];

        Assert.Equal("auto", c.EntrypointMode);
        Assert.Null(c.Ecosystem);
        Assert.Null(c.SymbolsPath);
        Assert.Null(c.EpssPath);
        Assert.Empty(c.Entrypoints);
    }

    [Fact]
    public void A_missing_file_bad_json_or_a_missing_version_is_refused()
    {
        Refused(Path.Combine(_root, "nope.json"), "not found");
        Refused(WriteRaw("{ not json"), "not valid JSON");
        Refused(WriteRaw("""{ "name": "x" }"""), "missing 'schemaVersion'");
        Refused(WriteRaw("""{ "schemaVersion": 2 }"""), "unsupported schemaVersion 2");
        Refused(WriteRaw("[]"), "missing 'schemaVersion'");
    }

    [Theory]
    [InlineData("top")]
    [InlineData("case")]
    [InlineData("label")]
    [InlineData("window")]
    public void An_unknown_property_is_an_error_at_every_level(string where)
    {
        string path = where switch
        {
            "top" => Write(top: """, "surprise": 1"""),
            "case" => Write(CaseJson(extra: """, "surprise": 1""")),
            "label" => Write(CaseJson(labels: """{ "advisory": "A", "package": "P", "exploited": true, "surprise": 1 }""")),
            _ => WriteRaw("""{ "schemaVersion": 1, "name": "n", "synthetic": true, "signalsAsOf": "2026-01-01", "labelSource": "l", "outcomeWindow": { "from": "2026-02-01", "to": "2026-03-01", "x": 1 }, "cases": [] }"""),
        };

        Refused(path, "unknown property 'surprise'".Replace("surprise", where == "window" ? "x" : "surprise"));
    }

    [Fact]
    public void Outcomes_must_be_observed_after_the_signals_were_fixed()
    {
        Refused(Write(asOf: "2026-02-01", from: "2026-01-15"), "before signalsAsOf");
        Refused(Write(from: "2026-03-01", to: "2026-03-01"), "must be after");
        Refused(Write(asOf: "2026-1-31"), "yyyy-MM-dd");

        // The day the signals were fixed is a valid first day of the window.
        Assert.NotNull(BenchManifestLoader.Load(Write(asOf: "2026-02-01", from: "2026-02-01")));
    }

    [Fact]
    public void Paths_must_be_relative_existing_and_inside_the_manifest_directory()
    {
        Refused(Write(CaseJson(path: Path.Combine(_root, "proj").Replace("\\", "\\\\"))), "relative path");
        Refused(Write(CaseJson(path: "../elsewhere")), "leaves the directory");
        Refused(Write(CaseJson(path: "proj/../../x")), "leaves the directory");
        Refused(Write(CaseJson(path: "missing")), "does not exist");
        Refused(Write(CaseJson(path: "/etc")), "relative path");
    }

    [Fact]
    public void A_path_through_a_symbolic_link_is_refused()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string target = Directory.CreateTempSubdirectory("deprisk-bench-link-").FullName;

        try
        {
            Directory.CreateSymbolicLink(Path.Combine(_root, "linked"), target);
            Directory.CreateDirectory(Path.Combine(target, "inner"));

            Refused(Write(CaseJson(path: "linked")), "symbolic link");
            Refused(Write(CaseJson(path: "linked/inner")), "symbolic link");
        }
        finally
        {
            Directory.Delete(target, recursive: true);
        }
    }

    [Fact]
    public void Cases_need_a_unique_safe_id_and_a_known_split()
    {
        Refused(Write(CaseJson("a") + "," + CaseJson("a")), "appears twice");
        Refused(Write(CaseJson("bad id")), "A-Z a-z 0-9");
        Refused(Write(CaseJson("../x")), "A-Z a-z 0-9");
        Refused(Write(CaseJson(split: "train")), "'dev' or 'test'");
        Refused(WriteRaw("""{ "schemaVersion": 1, "name": "n", "synthetic": true, "signalsAsOf": "2026-01-01", "labelSource": "l", "outcomeWindow": { "from": "2026-02-01", "to": "2026-03-01" }, "cases": [] }"""), "1 to 5000");
    }

    [Fact]
    public void Labels_are_unique_per_case_ignoring_case_and_carry_booleans_only()
    {
        string twice = Label + "," + Label.Replace("GHSA-1", "ghsa-1").Replace("Pkg", "PKG");
        Refused(Write(CaseJson(labels: twice)), "appears twice");
        Refused(Write(CaseJson(labels: """{ "advisory": "A", "package": "P", "exploited": "yes" }""")), "'exploited' in a label must be true or false");
        Refused(Write(CaseJson(labels: """{ "advisory": "A", "package": "P", "exploited": true, "reachable": "maybe" }""")), "true, false, or null");
        Refused(Write(CaseJson(labels: """{ "package": "P", "exploited": true }""")), "'advisory' is required");
    }

    [Fact]
    public void Text_with_control_characters_or_without_length_is_refused()
    {
        Refused(Write(CaseJson(labels: """{ "advisory": "A\u001b[31m", "package": "P", "exploited": true }""")), "control characters");
        Refused(Write(CaseJson(labels: """{ "advisory": "", "package": "P", "exploited": true }""")), "1 to 200 characters");
        Refused(Write(CaseJson(labels: $$"""{ "advisory": "{{new string('a', 201)}}", "package": "P", "exploited": true }""")), "1 to 200 characters");
    }

    [Fact]
    public void Ecosystem_entrypoint_options_and_their_dependence_on_symbols_are_checked()
    {
        Refused(Write(CaseJson(extra: ", \"ecosystem\": \"maven\"")), "not supported");
        Refused(Write(CaseJson(extra: ", \"symbols\": \"symbols/s.json\", \"entrypoints\": \"everything\"")), "must be one of");
        Refused(Write(CaseJson(extra: ", \"source\": \"proj\"")), "only apply together with 'symbols'");
        Refused(Write(CaseJson(extra: """, "entrypointNames": ["A.B"]""")), "only apply together with 'symbols'");
        Refused(Write(CaseJson(extra: """, "symbols": "symbols/s.json", "entrypointNames": [1]""")), "must hold strings");
    }

    [Fact]
    public void Top_level_fields_are_required_and_typed()
    {
        Refused(WriteRaw("""{ "schemaVersion": 1, "synthetic": true, "signalsAsOf": "2026-01-01", "labelSource": "l", "outcomeWindow": { "from": "2026-02-01", "to": "2026-03-01" }, "cases": [] }"""), "'name' is required");
        Refused(WriteRaw("""{ "schemaVersion": 1, "name": "n", "signalsAsOf": "2026-01-01", "labelSource": "l", "outcomeWindow": { "from": "2026-02-01", "to": "2026-03-01" }, "cases": [] }"""), "'synthetic'");
        Refused(WriteRaw("""{ "schemaVersion": 1, "name": "n", "synthetic": true, "signalsAsOf": "2026-01-01", "outcomeWindow": { "from": "2026-02-01", "to": "2026-03-01" }, "cases": [] }"""), "'labelSource' is required");
    }
}

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>deprisk bench calibrate on the synthetic smoke benchmark: its dev split has five findings with a reachability truth.</summary>
public sealed class BenchCalibrateCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-bench-fit-" + Guid.NewGuid().ToString("N"));

    private string Manifest => Path.Combine(_root, "bench-manifest.json");

    private string Out => Path.Combine(_root, "fitted.json");

    public BenchCalibrateCommandTests()
    {
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(Path.Combine(_root, "csharp"));
        File.WriteAllText(Path.Combine(_root, "csharp", "Program.cs"), "class P { }");

        foreach (string name in new[]
        {
            "bench-manifest.json",
            "assets/project.assets.json",
            "osv/DEPRISK-EXAMPLE-0001.json",
            "osv/DEPRISK-EXAMPLE-0002.json",
            "osv/DEPRISK-EXAMPLE-0003.json",
            "symbols/example.json",
            "kev/kev.json",
            "epss/epss.csv",
        })
        {
            string target = Path.Combine(_root, name.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllText(target, NpmFixtures.ReadReach(name), new UTF8Encoding(false));
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private string Analyzer => FakeAnalyzerScript.Create(_root);

    private (int Code, string Out, string Err) Calibrate(params string[] extra) =>
        Run(["bench", "calibrate", "--cases", Manifest, "--analyzer", Analyzer, "--out", Out, .. extra]);

    private void EditManifest(Action<JsonNode> edit)
    {
        JsonNode root = JsonNode.Parse(File.ReadAllText(Manifest))!;
        edit(root);
        File.WriteAllText(Manifest, root.ToJsonString(), new UTF8Encoding(false));
    }

    private static (double Alpha, double Beta) Beta(JsonElement reach, string name) =>
        (reach.GetProperty(name).GetProperty("alpha").GetDouble(), reach.GetProperty(name).GetProperty("beta").GetDouble());

    [Fact]
    public void With_the_default_minimum_a_tiny_dev_split_has_nothing_to_fit_and_nothing_is_written()
    {
        (int code, string output, string error) = Calibrate();

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("nothing to fit", error);
        Assert.Contains("5 findings with a known truth", error);
        Assert.False(File.Exists(Out));
    }

    [Fact]
    public void The_reach_factor_is_fitted_per_label_on_the_dev_split_with_a_uniform_prior()
    {
        (int code, string output, string error) = Calibrate("--min-count", "1");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("deprisk bench calibrate: synthetic-smoke, split dev: 2 case(s), 5 finding(s) with a reachability truth", output);
        Assert.Contains("WARNING: This dataset is synthetic", output);
        Assert.Contains("--split test --risk-params", output);

        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Out));
        JsonElement reach = doc.RootElement.GetProperty("reach");

        // reachable: 2 of 2 truly reachable, Beta(1 + 2, 1 + 0); unknown: 1 of 3, Beta(1 + 1, 1 + 2); the others have no observation and keep the defaults.
        Assert.Equal((3.0, 1.0), Beta(reach, "reachable"));
        Assert.Equal((2.0, 3.0), Beta(reach, "unknown"));
        Assert.Equal((4.0, 2.0), Beta(reach, "possiblyReachable"));
        Assert.Equal((1.0, 49.0), Beta(reach, "unreachable"));
        Assert.Equal((2.0, 2.0), Beta(reach, "notAnalyzed"));

        // A complete file: the other sections are written too, with a provenance note that says what it is.
        Assert.Equal(1, doc.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(20.0, doc.RootElement.GetProperty("exploit").GetProperty("epssConcentration").GetDouble());
        Assert.Equal(3.0, doc.RootElement.GetProperty("impact").GetProperty("low").GetDouble());

        string provenance = doc.RootElement.GetProperty("provenance").GetString()!;
        Assert.Contains("fitted by 'deprisk bench calibrate' on the dev split", provenance);
        Assert.Contains("SYNTHETIC: not evidence", provenance);
        Assert.Contains("reachable 2/2", provenance);
        Assert.Contains("Exploit and Impact are not fitted", provenance);
    }

    [Fact]
    public void The_current_parameters_can_be_the_prior()
    {
        Calibrate("--min-count", "1", "--prior", "current");

        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Out));
        JsonElement reach = doc.RootElement.GetProperty("reach");

        // Defaults Beta(9, 1) and Beta(2, 2) updated by 2 of 2 and 1 of 3.
        Assert.Equal((11.0, 1.0), Beta(reach, "reachable"));
        Assert.Equal((3.0, 4.0), Beta(reach, "unknown"));
    }

    [Fact]
    public void The_test_split_has_no_influence_on_the_fit()
    {
        Calibrate("--min-count", "1");
        string before = File.ReadAllText(Out);

        EditManifest(root =>
        {
            foreach (JsonNode? label in root["cases"]!.AsArray().Single(c => c!["id"]!.GetValue<string>() == "test-1")!["labels"]!.AsArray())
            {
                label!["reachable"] = true;
            }
        });

        Calibrate("--min-count", "1");

        // The manifest changed, so its digest in the provenance differs; the numbers must not.
        using JsonDocument a = JsonDocument.Parse(before);
        using JsonDocument b = JsonDocument.Parse(File.ReadAllText(Out));
        Assert.Equal(a.RootElement.GetProperty("reach").GetRawText(), b.RootElement.GetProperty("reach").GetRawText());
    }

    [Fact]
    public void The_fit_is_deterministic_and_the_file_has_no_byte_order_mark_and_lf_endings()
    {
        Calibrate("--min-count", "1");
        byte[] first = File.ReadAllBytes(Out);
        Calibrate("--min-count", "1");
        byte[] second = File.ReadAllBytes(Out);

        Assert.Equal(first, second);
        Assert.Equal((byte)'{', first[0]);
        Assert.DoesNotContain((byte)'\r', first);
        Assert.DoesNotContain(_root, Encoding.UTF8.GetString(first));
    }

    [Fact]
    public void A_fitted_file_is_accepted_by_rank_and_bench_and_reported_as_custom()
    {
        Calibrate("--min-count", "1");

        (int code, string output, _) = Run("bench", "--cases", Manifest, "--analyzer", Analyzer, "--split", "test", "--risk-params", Out, "--format", "json");
        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument doc = JsonDocument.Parse(output);
        Assert.Equal("custom", doc.RootElement.GetProperty("model").GetProperty("calibration").GetString());
        Assert.DoesNotContain(doc.RootElement.GetProperty("warnings").EnumerateArray(), w => w.GetString()!.Contains("fitted on the dev split", StringComparison.Ordinal));
    }

    [Fact]
    public void Evaluating_fitted_parameters_on_the_data_they_were_fitted_on_is_flagged()
    {
        Calibrate("--min-count", "1");

        foreach (string split in new[] { "dev", "all" })
        {
            (_, string output, _) = Run("bench", "--cases", Manifest, "--analyzer", Analyzer, "--split", split, "--risk-params", Out, "--format", "json");
            using JsonDocument doc = JsonDocument.Parse(output);

            Assert.Contains(doc.RootElement.GetProperty("warnings").EnumerateArray(), w => w.GetString()!.Contains("fitted on the dev split of this very dataset", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Parameters_the_fit_started_from_are_kept_outside_the_reach_section()
    {
        string start = Path.Combine(_root, "start.json");
        File.WriteAllText(start, """{ "schemaVersion": 1, "exploit": { "kevMean": 0.9 }, "reach": { "notAnalyzed": { "alpha": 5, "beta": 5 } } }""");

        Calibrate("--min-count", "1", "--risk-params", start);

        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Out));
        Assert.Equal(0.9, doc.RootElement.GetProperty("exploit").GetProperty("kevMean").GetDouble());
        Assert.Equal((5.0, 5.0), Beta(doc.RootElement.GetProperty("reach"), "notAnalyzed"));
        Assert.Equal((3.0, 1.0), Beta(doc.RootElement.GetProperty("reach"), "reachable"));
    }

    [Fact]
    public void A_benchmark_without_a_dev_case_is_refused()
    {
        EditManifest(root =>
        {
            foreach (JsonNode? c in root["cases"]!.AsArray())
            {
                c!["split"] = "test";
            }
        });

        (int code, _, string error) = Calibrate("--min-count", "1");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("no case in the 'dev' split", error);
        Assert.False(File.Exists(Out));
    }

    [Fact]
    public void Strict_refuses_findings_without_a_label()
    {
        EditManifest(root => root["cases"]![0]!["labels"]!.AsArray().RemoveAt(2));

        (int code, _, string error) = Calibrate("--min-count", "1", "--strict");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("--strict", error);
        Assert.False(File.Exists(Out));
    }

    [Fact]
    public void Options_are_validated()
    {
        Assert.Contains("needs a benchmark manifest", Run("bench", "calibrate", "--out", Out).Err);
        Assert.Contains("needs --out", Run("bench", "calibrate", "--cases", Manifest).Err);
        Assert.Contains("unknown option '--nope'", Calibrate("--nope").Err);
        Assert.Contains("takes no positional argument", Calibrate("extra").Err);
        Assert.Contains("--prior must be", Calibrate("--prior", "flat").Err);
        Assert.Contains("--min-count must be", Calibrate("--min-count", "0").Err);
        Assert.Contains("--min-count must be", Calibrate("--min-count", "x").Err);
        Assert.Contains("--timeout must be", Calibrate("--timeout", "0").Err);
        Assert.Contains("risk parameters not found", Calibrate("--risk-params", Path.Combine(_root, "nope.json")).Err);
        Assert.Contains("benchmark manifest not found", Run("bench", "calibrate", "--cases", Path.Combine(_root, "nope.json"), "--out", Out).Err);
    }

    [Fact]
    public void Help_lists_calibrate()
    {
        (_, string output, _) = Run("--help");

        Assert.Contains("bench calibrate --cases <manifest.json> --out <risk-params.json>", output);
    }
}

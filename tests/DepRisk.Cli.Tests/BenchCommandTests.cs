using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>deprisk bench on the synthetic smoke benchmark (tests/fixtures/reach/bench-manifest.json) with a stand-in analyzer.</summary>
public sealed class BenchCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-bench-cli-" + Guid.NewGuid().ToString("N"));

    private string Manifest => Path.Combine(_root, "bench-manifest.json");

    public BenchCommandTests()
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

    private string[] Bench(params string[] extra) => ["bench", "--cases", Manifest, "--analyzer", Analyzer, .. extra];

    private void EditManifest(Action<JsonNode> edit)
    {
        JsonNode root = JsonNode.Parse(File.ReadAllText(Manifest))!;
        edit(root);
        File.WriteAllText(Manifest, root.ToJsonString(), new UTF8Encoding(false));
    }

    private static JsonDocument Parse(string json) => JsonDocument.Parse(json);

    [Fact]
    public void Table_output_names_the_dataset_the_split_and_every_method_and_says_the_data_is_synthetic()
    {
        (int code, string output, string error) = Run(Bench());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("deprisk bench: synthetic-smoke, split dev: 2 case(s), 6 labeled finding(s), 2 exploited", output);
        Assert.Contains("WARNING: This dataset is synthetic", output);
        Assert.Contains("signals as of 2026-01-31", output);

        foreach (string method in new[] { "b1-cvss", "b2-baseline", "b3-reachable-only", "b3c-not-unreachable", "deprisk-risk" })
        {
            Assert.Contains(method, output);
        }

        Assert.Contains("unsound 'unreachable' calls: 0 of 0", output);
        Assert.Contains("Not evaluated yet:", output);
        Assert.Contains("baseline-b4-upgrade-everything", output);
        Assert.DoesNotContain(_root, output);
    }

    [Fact]
    public void Json_output_carries_the_result_and_is_identical_on_every_run()
    {
        (_, string first, _) = Run(Bench("--format", "json"));
        (_, string second, _) = Run(Bench("--format", "json"));

        Assert.Equal(first, second);
        Assert.DoesNotContain(_root, first);

        using JsonDocument doc = Parse(first);
        JsonElement root = doc.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("dev", root.GetProperty("split").GetString());
        Assert.True(root.GetProperty("dataset").GetProperty("synthetic").GetBoolean());
        Assert.Equal("2026-01-31", root.GetProperty("dataset").GetProperty("signalsAsOf").GetString());
        Assert.Equal(64, root.GetProperty("dataset").GetProperty("digest").GetString()!.Length);
        Assert.Equal("uncalibrated-defaults", root.GetProperty("model").GetProperty("calibration").GetString());

        Assert.Equal(
            new[] { "b1-cvss", "b2-baseline", "b3-reachable-only", "b3c-not-unreachable", "deprisk-risk" },
            root.GetProperty("methods").EnumerateArray().Select(m => m.GetProperty("id").GetString()!).ToArray());

        JsonElement counts = root.GetProperty("counts");
        Assert.Equal(2, counts.GetProperty("cases").GetInt32());
        Assert.Equal(6, counts.GetProperty("labeled").GetInt32());
        Assert.Equal(0, counts.GetProperty("unlabeled").GetInt32());
        Assert.Equal(0, counts.GetProperty("labelsUnmatched").GetInt32());
        Assert.Equal(5, root.GetProperty("notEvaluated").GetArrayLength());
    }

    [Fact]
    public void A_label_given_by_alias_is_joined_to_the_finding()
    {
        // dev-2 labels the first advisory as CVE-2099-0001, an alias; all six findings of the dev split are labeled.
        (_, string output, _) = Run(Bench("--format", "json"));
        using JsonDocument doc = Parse(output);

        Assert.Equal(0, doc.RootElement.GetProperty("counts").GetProperty("unlabeled").GetInt32());
    }

    [Fact]
    public void The_baseline_and_the_naive_reachability_filter_differ_as_the_labels_say()
    {
        (_, string output, _) = Run(Bench("--format", "json", "--bootstrap", "0"));
        using JsonDocument doc = Parse(output);

        JsonElement[] methods = doc.RootElement.GetProperty("methods").EnumerateArray().ToArray();
        JsonElement b2 = methods.Single(m => m.GetProperty("id").GetString() == "b2-baseline");
        JsonElement b3 = methods.Single(m => m.GetProperty("id").GetString() == "b3-reachable-only");

        // KEV puts the first advisory on top. In dev-1 it is the exploited one (AP 1), in dev-2 the exploited one is second (AP 0.5).
        Assert.Equal(0.75, b2.GetProperty("averagePrecision").GetDouble());
        Assert.Equal(0, b2.GetProperty("exploitedMissed").GetInt32());

        // The naive filter drops the unknown verdicts, among them the exploited finding of dev-2.
        Assert.Equal(0.5, b3.GetProperty("averagePrecision").GetDouble());
        Assert.Equal(1, b3.GetProperty("exploitedMissed").GetInt32());
        Assert.Equal(4, b3.GetProperty("suppressed").GetInt32());
    }

    [Fact]
    public void Reachability_is_evaluated_against_the_labeled_truth()
    {
        (_, string output, _) = Run(Bench("--format", "json"));
        using JsonDocument doc = Parse(output);
        JsonElement reach = doc.RootElement.GetProperty("reach");

        Assert.Equal(5, reach.GetProperty("evaluated").GetInt32());
        Assert.Equal(0, reach.GetProperty("unsoundUnreachable").GetInt32());
        Assert.Equal(4, reach.GetProperty("rows").GetArrayLength());
    }

    [Fact]
    public void The_test_split_and_all_cases_are_selectable_and_say_what_that_means()
    {
        (int code, string output, _) = Run(Bench("--split", "test", "--format", "json"));
        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument test = Parse(output);
        Assert.Equal(1, test.RootElement.GetProperty("counts").GetProperty("cases").GetInt32());
        Assert.Contains(test.RootElement.GetProperty("warnings").EnumerateArray(), w => w.GetString()!.StartsWith("Test split", StringComparison.Ordinal));
        Assert.Contains("at least 2 cases", test.RootElement.GetProperty("bootstrap").GetProperty("notComputedReason").GetString());
        Assert.Contains(test.RootElement.GetProperty("warnings").EnumerateArray(), w => w.GetString()!.Contains("no symbol maps", StringComparison.Ordinal));

        (_, string all, _) = Run(Bench("--split", "all", "--format", "json"));
        using JsonDocument everything = Parse(all);
        Assert.Equal(3, everything.RootElement.GetProperty("counts").GetProperty("cases").GetInt32());
        Assert.Contains(everything.RootElement.GetProperty("warnings").EnumerateArray(), w => w.GetString()!.Contains("not a held-out result", StringComparison.Ordinal));
    }

    [Fact]
    public void A_split_without_cases_is_refused()
    {
        EditManifest(root =>
        {
            foreach (JsonNode? c in root["cases"]!.AsArray())
            {
                c!["split"] = "dev";
            }
        });

        (int code, _, string error) = Run(Bench("--split", "test"));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("no case in the split 'test'", error);
    }

    [Fact]
    public void Signals_newer_than_the_date_they_were_fixed_at_are_refused_as_leakage()
    {
        EditManifest(root =>
        {
            root["signalsAsOf"] = "2026-01-10";
            root["outcomeWindow"]!["from"] = "2026-01-11";
        });

        (int code, string output, string error) = Run(Bench());

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("leakage guard", error);
        Assert.Contains("2026-01-15", error);
        Assert.Contains("case 'dev-1'", error);
    }

    [Fact]
    public void Signals_without_a_readable_date_cannot_be_shown_to_predate_the_outcomes_and_are_refused()
    {
        File.WriteAllText(Path.Combine(_root, "epss", "epss.csv"), "cve,epss,percentile\nCVE-2099-0001,0.4,0.9\n");

        (int code, _, string error) = Run(Bench());

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("no readable publication date", error);
        Assert.Contains("EPSS", error);
    }

    [Fact]
    public void A_kev_catalog_released_after_the_signals_date_is_refused_even_if_epss_is_fine()
    {
        string kev = File.ReadAllText(Path.Combine(_root, "kev", "kev.json")).Replace("2026-01-15T12:00:00.0000Z", "2026-03-01T12:00:00.0000Z");
        File.WriteAllText(Path.Combine(_root, "kev", "kev.json"), kev);

        (int code, _, string error) = Run(Bench());

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("KEV", error);
        Assert.Contains("2026-03-01", error);
    }

    [Fact]
    public void Strict_refuses_findings_without_a_label_and_labels_without_a_finding_and_plain_runs_only_warn()
    {
        EditManifest(root =>
        {
            JsonArray labels = root["cases"]![0]!["labels"]!.AsArray();
            labels.RemoveAt(2);
            labels.Add(JsonNode.Parse("""{ "advisory": "GHSA-none", "package": "Nothing", "exploited": false }"""));
        });

        (int strictCode, _, string strictError) = Run(Bench("--strict"));
        Assert.Equal((int)ExitCode.InvalidInput, strictCode);
        Assert.Contains("1 finding(s) have no label and 1 label(s) match no finding", strictError);

        (int code, string output, _) = Run(Bench("--format", "json"));
        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument doc = Parse(output);
        Assert.Equal(1, doc.RootElement.GetProperty("counts").GetProperty("unlabeled").GetInt32());
        Assert.Equal(1, doc.RootElement.GetProperty("counts").GetProperty("labelsUnmatched").GetInt32());
        Assert.Equal(5, doc.RootElement.GetProperty("counts").GetProperty("labeled").GetInt32());
    }

    [Fact]
    public void A_manifest_that_points_outside_its_directory_is_refused_before_anything_is_read()
    {
        EditManifest(root => root["cases"]![0]!["advisories"] = "../osv");

        (int code, _, string error) = Run(Bench());

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("leaves the directory of the manifest", error);
    }

    [Fact]
    public void Model_options_are_passed_to_the_risk_model_and_recorded()
    {
        (_, string output, _) = Run(Bench("--format", "json", "--samples", "200", "--seed", "7", "--rank-by", "p95", "--bootstrap", "50"));
        using JsonDocument doc = Parse(output);
        JsonElement model = doc.RootElement.GetProperty("model");

        Assert.Equal(200, model.GetProperty("samples").GetInt32());
        Assert.Equal("7", model.GetProperty("seed").GetString());
        Assert.Equal("p95", model.GetProperty("rankBy").GetString());
        Assert.Equal(50, doc.RootElement.GetProperty("bootstrap").GetProperty("iterations").GetInt32());
        Assert.Equal("7", doc.RootElement.GetProperty("bootstrap").GetProperty("seed").GetString());
    }

    [Fact]
    public void The_same_seed_gives_the_same_result_and_another_seed_changes_the_model_record()
    {
        (_, string a, _) = Run(Bench("--format", "json", "--seed", "1", "--samples", "300"));
        (_, string b, _) = Run(Bench("--format", "json", "--seed", "1", "--samples", "300"));
        (_, string c, _) = Run(Bench("--format", "json", "--seed", "2", "--samples", "300"));

        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
    }

    [Fact]
    public void Out_writes_the_result_to_a_file_without_a_byte_order_mark()
    {
        string file = Path.Combine(_root, "result.json");
        (int code, string output, _) = Run(Bench("--format", "json", "--out", file));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.StartsWith("Wrote json benchmark result to ", output);
        Assert.Contains("6 labeled finding(s) in 2 case(s)", output);

        byte[] bytes = File.ReadAllBytes(file);
        Assert.NotEqual((byte)0xEF, bytes[0]);
        Assert.Equal((byte)'{', bytes[0]);

        using JsonDocument doc = Parse(File.ReadAllText(file));
        Assert.Equal("synthetic-smoke", doc.RootElement.GetProperty("dataset").GetProperty("name").GetString());
    }

    [Fact]
    public void Options_are_validated()
    {
        string[] noCases = ["bench"];
        Assert.Contains("needs a benchmark manifest", Run(noCases).Err);
        Assert.Equal((int)ExitCode.InvalidInput, Run(noCases).Code);

        Assert.Contains("unknown option '--nope'", Run(Bench("--nope")).Err);
        Assert.Contains("takes no positional argument", Run(Bench("extra")).Err);
        Assert.Contains("--split must be one of", Run(Bench("--split", "train")).Err);
        Assert.Contains("--samples must be", Run(Bench("--samples", "3")).Err);
        Assert.Contains("--samples must be", Run(Bench("--samples", "abc")).Err);
        Assert.Contains("--seed must be", Run(Bench("--seed", "-1")).Err);
        Assert.Contains("--rank-by must be", Run(Bench("--rank-by", "median")).Err);
        Assert.Contains("--bootstrap must be", Run(Bench("--bootstrap", "99999")).Err);
        Assert.Contains("--bootstrap must be", Run(Bench("--bootstrap", "-1")).Err);
        Assert.Contains("--timeout must be", Run(Bench("--timeout", "0")).Err);
        Assert.Contains("format 'xml' is not supported", Run(Bench("--format", "xml")).Err);
        Assert.Contains("risk parameters not found", Run(Bench("--risk-params", Path.Combine(_root, "nope.json"))).Err);
        Assert.Contains("benchmark manifest not found", Run("bench", "--cases", Path.Combine(_root, "nope.json")).Err);
    }

    [Fact]
    public void Help_lists_the_command_and_the_planned_list_no_longer_does()
    {
        (int code, string output, _) = Run("--help");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("bench --cases <manifest.json>", output);
        Assert.DoesNotContain("explain, vex, bundle, bench", output);
    }
}

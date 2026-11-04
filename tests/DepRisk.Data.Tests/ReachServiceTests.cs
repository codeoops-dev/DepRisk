using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class ReachServiceTests : IDisposable
{
    private static readonly ToolInfo Tool = new("deprisk", "0.0.0-test");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-reach-svc-" + Guid.NewGuid().ToString("N"));

    private string Project => Path.Combine(_root, "proj");

    private string Osv => Path.Combine(_root, "osv");

    private string Symbols => Path.Combine(_root, "symbols");

    private string Analyzer => Path.Combine(_root, "bin", "deprisk-reach-fake");

    public ReachServiceTests()
    {
        Directory.CreateDirectory(Project);
        Directory.CreateDirectory(Osv);
        Directory.CreateDirectory(Symbols);
        Directory.CreateDirectory(Path.GetDirectoryName(Analyzer)!);
        File.WriteAllText(Analyzer, "pretend this is an executable");
        File.WriteAllText(Path.Combine(Project, "project.assets.json"), NpmFixtures.ReadReach("assets/project.assets.json"));

        foreach (string id in new[] { "0001", "0002", "0003" })
        {
            File.WriteAllText(Path.Combine(Osv, $"DEPRISK-EXAMPLE-{id}.json"), NpmFixtures.ReadReach($"osv/DEPRISK-EXAMPLE-{id}.json"));
        }

        File.WriteAllText(Path.Combine(Symbols, "example.json"), NpmFixtures.ReadReach("symbols/example.json"));
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private ReachOptions Options(string? source = null, string? analyzer = null, string? symbols = null, Ecosystem? ecosystem = null, string scan = "") =>
        new(
            scan.Length == 0 ? Project : scan,
            Osv,
            symbols ?? Symbols,
            source,
            ecosystem,
            false,
            "auto",
            [],
            analyzer ?? Analyzer,
            TimeSpan.FromSeconds(5),
            _root);

    private static ReachOutcome Run(ReachOptions options, FakeAnalyzer fake) =>
        ReachService.Run(options, Tool, fake, _ => null, AppContext.BaseDirectory);

    private static ReachVerdict VerdictOf(ReachOutcome outcome, string advisory) => Assert.Single(outcome.Result.Findings, f => f.Finding.Id == advisory).Reachability;

    private static string PerKey(string request, Func<string, (string Label, string Reason, string? Symbol)> verdict)
    {
        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(request);
        string[] keys = document.RootElement.GetProperty("targets").EnumerateArray().Select(t => t.GetProperty("key").GetString()!).ToArray();
        string template = FakeAnalyzer.Result(request, "unreachable", "no-path");
        string results = string.Join(
            ",",
            keys.Select(k =>
            {
                (string label, string reason, string? symbol) = verdict(k);
                string path = symbol is null ? "[]" : $$"""[{"from":"Sample.Program.Main","to":"{{symbol}}","kind":"static","file":"Program.cs","line":12}]""";
                return $$"""{"key":"{{k}}","label":"{{label}}","reason":"{{reason}}","path":{{path}},"symbol":{{(symbol is null ? "null" : "\"" + symbol + "\"")}}}""";
            }));
        int start = template.IndexOf("\"results\":[", StringComparison.Ordinal) + "\"results\":[".Length;
        int end = template.IndexOf("],\"diagnostics\"", StringComparison.Ordinal);

        return template[..start] + results + template[end..];
    }

    private static FakeAnalyzer Standard() => new((_, request) => PerKey(request, key => key.StartsWith("DEPRISK-EXAMPLE-0001", StringComparison.Ordinal)
        ? ("reachable", "static-path", "Newtonsoft.Json.JsonConvert.DeserializeObject")
        : ("unreachable", "no-path", null)));

    [Fact]
    public void Each_finding_gets_the_verdict_for_its_advisory_and_package()
    {
        FakeAnalyzer fake = Standard();

        ReachOutcome outcome = Run(Options(), fake);
        ReachabilityResult result = outcome.Result;

        Assert.Equal("nuget", result.Ecosystem);
        Assert.Equal(3, result.Findings.Count);

        ReachVerdict reached = VerdictOf(outcome, "DEPRISK-EXAMPLE-0001");
        Assert.Equal(ReachLabels.Reachable, reached.Label);
        Assert.Equal(ReachLabels.StaticPath, reached.Reason);
        Assert.Equal("Newtonsoft.Json.JsonConvert.DeserializeObject", reached.Symbol);
        Assert.Equal("Sample.Program.Main", Assert.Single(reached.Path).From);
        Assert.Contains("example only", reached.SymbolSources[0]);   // the entry was found through the alias CVE-2099-0001

        ReachVerdict transitive = VerdictOf(outcome, "DEPRISK-EXAMPLE-0002");
        Assert.Equal(ReachLabels.Unknown, transitive.Label);
        Assert.Equal(ReachLabels.TransitivePackage, transitive.Reason);

        ReachVerdict none = VerdictOf(outcome, "DEPRISK-EXAMPLE-0003");
        Assert.Equal(ReachLabels.Unknown, none.Label);
        Assert.Equal(ReachLabels.NoSymbols, none.Reason);
        Assert.Empty(none.SymbolSources);

        Assert.Equal(new ReachSummary(1, 0, 0, 2), result.Summary);
    }

    [Fact]
    public void Only_findings_with_symbols_are_sent_and_the_completeness_claim_is_passed_on()
    {
        FakeAnalyzer fake = Standard();

        Run(Options(), fake);

        using System.Text.Json.JsonDocument request = System.Text.Json.JsonDocument.Parse(fake.LastRequest!);
        System.Text.Json.JsonElement[] targets = request.RootElement.GetProperty("targets").EnumerateArray().ToArray();

        Assert.Equal(2, targets.Length);   // 0003 has no symbol list: it is not asked about
        Assert.Equal("DEPRISK-EXAMPLE-0001|Newtonsoft.Json", targets[0].GetProperty("key").GetString());
        Assert.False(targets[0].GetProperty("complete").GetBoolean());
        Assert.Equal("DEPRISK-EXAMPLE-0002|Example.Lib", targets[1].GetProperty("key").GetString());
        Assert.True(targets[1].GetProperty("complete").GetBoolean());
        Assert.Equal("auto", request.RootElement.GetProperty("entrypoints").GetProperty("mode").GetString());
        Assert.Equal(Project, request.RootElement.GetProperty("root").GetString());
        Assert.Equal(Analyzer, fake.LastExecutable);
    }

    [Fact]
    public void Findings_are_ordered_by_urgency()
    {
        ReachOutcome outcome = Run(Options(), Standard());

        Assert.Equal(
            new[] { ReachLabels.Reachable, ReachLabels.Unknown, ReachLabels.Unknown },
            outcome.Result.Findings.Select(f => f.Reachability.Label).ToArray());
        Assert.Equal("DEPRISK-EXAMPLE-0001", outcome.Result.Findings[0].Finding.Id);
    }

    [Fact]
    public void A_transitive_package_can_still_be_reachable_because_a_path_is_real_evidence()
    {
        FakeAnalyzer fake = new((_, request) => PerKey(request, key => key.StartsWith("DEPRISK-EXAMPLE-0002", StringComparison.Ordinal)
            ? ("reachable", "static-path", "Example.Lib.Thing.Run")
            : ("unreachable", "no-path", null)));

        ReachVerdict verdict = VerdictOf(Run(Options(), fake), "DEPRISK-EXAMPLE-0002");

        Assert.Equal(ReachLabels.Reachable, verdict.Label);
    }

    [Fact]
    public void Possibly_reachable_and_other_unknown_reasons_pass_through_unchanged()
    {
        FakeAnalyzer fake = new((_, request) => PerKey(request, key => key.StartsWith("DEPRISK-EXAMPLE-0001", StringComparison.Ordinal)
            ? ("possibly-reachable", "dynamic-path", "Newtonsoft.Json.JsonConvert.DeserializeObject")
            : ("unknown", "unresolved-reflection", null)));

        ReachOutcome outcome = Run(Options(), fake);

        Assert.Equal(ReachLabels.PossiblyReachable, VerdictOf(outcome, "DEPRISK-EXAMPLE-0001").Label);
        Assert.Equal(ReachLabels.UnresolvedReflection, VerdictOf(outcome, "DEPRISK-EXAMPLE-0002").Reason);
    }

    [Fact]
    public void A_direct_package_with_no_path_and_a_complete_list_is_unreachable()
    {
        File.WriteAllText(Path.Combine(Symbols, "other.json"), """
            { "schemaVersion": 1, "language": "csharp", "entries": [
              { "advisory": "DEPRISK-EXAMPLE-0003", "package": "Other.Lib", "symbols": ["Other.Lib.Thing.Run"], "complete": true, "source": "test" } ] }
            """);

        ReachOutcome outcome = Run(Options(), new FakeAnalyzer());

        Assert.Equal(ReachLabels.Unreachable, VerdictOf(outcome, "DEPRISK-EXAMPLE-0003").Label);
        Assert.Equal(2, outcome.Result.Summary.Unreachable);   // 0001 and 0003; 0002 is transitive and therefore unknown
    }

    [Fact]
    public void Nothing_to_ask_means_the_analyzer_is_neither_needed_nor_run()
    {
        File.WriteAllText(Path.Combine(Symbols, "example.json"), """{ "schemaVersion": 1, "language": "csharp", "entries": [] }""");
        FakeAnalyzer fake = Standard();

        ReachOutcome outcome = ReachService.Run(Options(analyzer: Path.Combine(_root, "does-not-exist-but-never-looked-up")), Tool, fake, _ => null, Path.Combine(_root, "empty"));

        Assert.Equal(0, fake.Calls);
        Assert.Null(outcome.Result.Analyzer);
        Assert.Null(outcome.Result.Source);
        Assert.All(outcome.Result.Findings, f => Assert.Equal(ReachLabels.NoSymbols, f.Reachability.Reason));
    }

    [Fact]
    public void Without_an_analyzer_the_command_fails_clearly()
    {
        ReachOptions options = Options() with { AnalyzerPath = null };

        InvalidInputException error = Assert.Throws<InvalidInputException>(
            () => ReachService.Run(options, Tool, Standard(), _ => null, Path.Combine(_root, "empty")));

        Assert.Contains("needs the analyzer", error.Message);
        Assert.Contains("cargo build", error.Message);
    }

    [Fact]
    public void The_analyzer_is_recorded_by_name_version_and_the_hash_of_the_executable()
    {
        ReachOutcome outcome = Run(Options(), Standard());

        Assert.Equal("deprisk-reach", outcome.Result.Analyzer!.Name);
        Assert.Equal("9.9.9", outcome.Result.Analyzer.Version);
        Assert.Equal(Digest.Sha256Hex(File.ReadAllBytes(Analyzer)), outcome.Result.Analyzer.Sha256);
        Assert.Equal(new string('a', 64), outcome.Result.Source!.SourceDigest);
        Assert.Equal(3, outcome.Result.Source.Files);
    }

    [Fact]
    public void A_failing_analyzer_is_an_error_with_a_safe_message()
    {
        FakeAnalyzer fake = new() { ExitCode = 2, StdErr = "deprisk-reach: bad root \u001b[31mevil\nsecond line" };

        AnalyzerException error = Assert.Throws<AnalyzerException>(() => Run(Options(), fake));

        Assert.Contains("exit code 2", error.Message);
        Assert.Contains("bad root", error.Message);
        Assert.False(error.Message.Contains('\u001b'));
        Assert.DoesNotContain("second line", error.Message);
    }

    [Fact]
    public void A_result_that_does_not_match_the_request_is_an_error()
    {
        FakeAnalyzer fake = new((_, request) => FakeAnalyzer.Result(request, "reachable", "static-path", "A.B.C").Replace("DEPRISK-EXAMPLE-0001|Newtonsoft.Json", "somebody-else", StringComparison.Ordinal));

        Assert.Throws<AnalyzerException>(() => Run(Options(), fake));
    }

    [Fact]
    public void Unreadable_source_is_called_out_in_the_notes()
    {
        FakeAnalyzer fake = new((_, request) => FakeAnalyzer.Result(request, "unknown", "incomplete-analysis", filesWithErrors: 2));

        ReachabilityResult result = Run(Options(), fake).Result;

        Assert.Contains("2 file(s) could not be read completely", result.Diagnostics[0]);
        Assert.Equal(2, result.Source!.FilesWithErrors);
    }

    [Fact]
    public void The_source_root_is_the_scan_directory_unless_named_and_must_exist()
    {
        FakeAnalyzer fake = Standard();
        string src = Path.Combine(_root, "elsewhere");
        Directory.CreateDirectory(src);

        Run(Options(source: src), fake);
        using (System.Text.Json.JsonDocument request = System.Text.Json.JsonDocument.Parse(fake.LastRequest!))
        {
            Assert.Equal(src, request.RootElement.GetProperty("root").GetString());
        }

        Run(Options(scan: Path.Combine(Project, "project.assets.json")), fake);
        using (System.Text.Json.JsonDocument request = System.Text.Json.JsonDocument.Parse(fake.LastRequest!))
        {
            Assert.Equal(Project, request.RootElement.GetProperty("root").GetString());   // a file: its directory
        }

        Assert.Contains("source directory not found", Assert.Throws<InvalidInputException>(() => Run(Options(source: Path.Combine(_root, "nope")), fake)).Message);
    }

    [Fact]
    public void Npm_has_no_analyzer_yet_and_says_so_without_running_one()
    {
        string npm = Path.Combine(_root, "npm");
        Directory.CreateDirectory(npm);
        File.WriteAllText(Path.Combine(npm, "package-lock.json"), NpmFixtures.Read(NpmFixtures.Simple));
        string osv = Path.Combine(_root, "osv-npm");
        Directory.CreateDirectory(osv);
        File.WriteAllText(Path.Combine(osv, "t.json"), """
            { "id": "T-1", "affected": [ { "package": { "ecosystem": "npm", "name": "ms" }, "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "2.1.3" } ] } ] } ] }
            """);
        string symbols = Path.Combine(_root, "npm-symbols.json");
        File.WriteAllText(symbols, """
            { "schemaVersion": 1, "language": "csharp", "entries": [ { "advisory": "T-1", "package": "ms", "symbols": ["A.B.C"], "complete": true, "source": "test" } ] }
            """);
        FakeAnalyzer fake = Standard();

        ReachOutcome outcome = Run(Options(scan: npm, symbols: symbols) with { AdvisoriesPath = osv }, fake);

        Assert.Equal(0, fake.Calls);
        Assert.Equal("npm", outcome.Result.Ecosystem);
        ReachVerdict verdict = Assert.Single(outcome.Result.Findings).Reachability;
        Assert.Equal(ReachLabels.Unknown, verdict.Label);
        Assert.Equal(ReachLabels.NoAnalyzerForEcosystem, verdict.Reason);
    }

    [Fact]
    public void The_inputs_digest_covers_the_findings_the_symbols_the_analyzer_and_the_source()
    {
        string baseline = Run(Options(), Standard()).InputsDigest;

        Assert.Equal(baseline, Run(Options(), Standard()).InputsDigest);

        File.WriteAllText(Path.Combine(Symbols, "example.json"), NpmFixtures.ReadReach("symbols/example.json").Replace("DeserializeObject", "SerializeObject", StringComparison.Ordinal));
        string symbolsChanged = Run(Options(), Standard()).InputsDigest;
        Assert.NotEqual(baseline, symbolsChanged);

        File.WriteAllText(Analyzer, "a different analyzer build");
        string analyzerChanged = Run(Options(), Standard()).InputsDigest;
        Assert.NotEqual(symbolsChanged, analyzerChanged);

        FakeAnalyzer otherSource = new((_, request) => FakeAnalyzer.Result(request, "unreachable", "no-path").Replace(new string('a', 64), new string('b', 64), StringComparison.Ordinal));
        Assert.NotEqual(analyzerChanged, Run(Options(), otherSource).InputsDigest);
    }

    [Fact]
    public void The_json_is_deterministic_and_has_no_machine_specific_path()
    {
        string one = ReachabilityResultJson.Serialize(Run(Options(), Standard()).Result);
        string two = ReachabilityResultJson.Serialize(Run(Options(), Standard()).Result);

        Assert.Equal(one, two);
        Assert.DoesNotContain(_root, one);
        Assert.Contains("\"label\": \"reachable\"", one);
        Assert.Contains("\"ecosystem\": \"nuget\"", one);
    }
}

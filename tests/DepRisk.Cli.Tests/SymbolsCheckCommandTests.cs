using System.Text;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary><c>deprisk symbols check</c> (ADR 0025) on the npm fixture (tests/fixtures/reach-npm).</summary>
public sealed class SymbolsCheckCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-symcheck-cli-" + Guid.NewGuid().ToString("N"));

    private string Osv => Path.Combine(_root, "osv");

    private string Symbols => Path.Combine(_root, "symbols");

    public SymbolsCheckCommandTests()
    {
        Directory.CreateDirectory(_root);

        foreach (string name in new[]
        {
            "package.json",
            "package-lock.json",
            "osv/DEPRISK-NPM-0001.json",
            "osv/DEPRISK-NPM-0002.json",
            "osv/DEPRISK-NPM-0003.json",
            "osv/DEPRISK-NPM-0004.json",
            "src/app.js",
            "symbols/npm-example.json",
        })
        {
            // The lockfile is stored as package-lock.fixture.json: a file called package-lock.json in the repository would make a scan of
            // the repository root find both ecosystems.
            string target = Path.Combine(_root, name.Replace('/', Path.DirectorySeparatorChar));
            string resource = name == "package-lock.json" ? "package-lock.fixture.json" : name;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllText(target, NpmFixtures.ReadReachNpm(resource), new UTF8Encoding(false));
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

    private string[] Check(params string[] extra) => ["symbols", "check", _root, "--advisories", Osv, "--symbols", Symbols, .. extra];

    private void AddMap(string name, string json) => File.WriteAllText(Path.Combine(Symbols, name), json);

    [Fact]
    public void The_fixture_map_fits_the_project_and_the_report_says_what_it_claims_less_of()
    {
        (int code, string output, string error) = Run(Check());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("4 entries for javascript, 4 advisory/package pair(s) in the project; ecosystem npm", output);
        Assert.Contains("summary: 4 apply (3 complete, 1 incomplete), 0 unused, 0 missing, 0 not writable", output);
        Assert.Contains("incomplete     DEPRISK-NPM-0004  @scope/client", output);
        Assert.Contains("transitive     DEPRISK-NPM-0003  deep-lib", output);
        Assert.Contains("not that the symbols are right", output);
    }

    [Fact]
    public void An_entry_that_no_longer_fits_the_project_is_listed_as_unused()
    {
        AddMap("stale.json", """{"schemaVersion":1,"language":"javascript","entries":[{"advisory":"GHSA-gone","package":"removed-lib","symbols":["*"],"complete":true,"source":"old"}]}""");

        (int code, string output, _) = Run(Check());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("1 unused", output);
        Assert.Contains("unused         GHSA-gone  removed-lib", output);
    }

    [Fact]
    public void Pairs_without_an_entry_are_listed_as_missing_with_the_way_to_draft_them()
    {
        File.Delete(Path.Combine(Symbols, "npm-example.json"));
        AddMap("one.json", """{"schemaVersion":1,"language":"javascript","entries":[{"advisory":"CVE-2099-1001","package":"example-lib","symbols":["parse"],"complete":true,"source":"test"}]}""");

        (int code, string output, _) = Run(Check());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("1 apply (1 complete, 0 incomplete), 0 unused, 3 missing", output);
        Assert.Contains("missing        DEPRISK-NPM-0002  other-lib 2.0.0 (direct)", output);
        Assert.Contains("'deprisk symbols template' drafts one", output);
    }

    [Fact]
    public void Entries_for_the_other_language_are_counted_as_ignored()
    {
        AddMap("cs.json", """{"schemaVersion":1,"language":"csharp","entries":[{"advisory":"X-1","package":"Some.Lib","symbols":["Some.Lib.T.Run"],"complete":true,"source":"test"}]}""");

        (_, string output, _) = Run(Check());

        Assert.Contains("ignored: 1 entry for the other language", output);
        Assert.Contains("4 entries for javascript", output);
    }

    [Fact]
    public void Without_fail_on_the_exit_code_is_zero_whatever_the_report_says()
    {
        File.Delete(Path.Combine(Symbols, "npm-example.json"));
        AddMap("empty.json", """{"schemaVersion":1,"language":"javascript","entries":[]}""");

        (int code, string output, string error) = Run(Check());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("4 missing", output);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void The_gate_fails_with_exit_1_and_names_the_conditions_on_standard_error()
    {
        AddMap("stale.json", """{"schemaVersion":1,"language":"javascript","entries":[{"advisory":"GHSA-gone","package":"removed-lib","symbols":["*"],"complete":true,"source":"old"}]}""");

        (int code, string output, string error) = Run(Check("--fail-on", "unused,incomplete"));

        Assert.Equal((int)ExitCode.PolicyGateFailed, code);
        Assert.Contains("summary:", output);
        Assert.Contains("symbols check gate failed (incomplete: 1, unused: 1)", error);
    }

    [Fact]
    public void A_gate_that_holds_exits_zero()
    {
        (int code, _, string error) = Run(Check("--fail-on", "missing,unused"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void The_missing_gate_fires_for_a_pair_that_has_no_entry()
    {
        File.Delete(Path.Combine(Symbols, "npm-example.json"));
        AddMap("empty.json", """{"schemaVersion":1,"language":"javascript","entries":[]}""");

        (int code, _, string error) = Run(Check("--fail-on", "missing"));

        Assert.Equal((int)ExitCode.PolicyGateFailed, code);
        Assert.Contains("missing: 4", error);
    }

    [Fact]
    public void A_draft_that_is_not_filled_in_is_refused_not_checked()
    {
        Assert.Equal((int)ExitCode.Success, Run("symbols", "template", _root, "--advisories", Osv, "--format", "json", "--out", Path.Combine(Symbols, "draft.json")).Code);

        (int code, string output, string error) = Run(Check());

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("draft.json", error);
    }

    [Fact]
    public void Control_characters_in_a_map_are_refused_by_the_loader_before_anything_is_printed()
    {
        // The report prints the source of an entry; the loader already refuses control characters there, so none can reach the terminal.
        AddMap("evil.json", "{\"schemaVersion\":1,\"language\":\"javascript\",\"entries\":[{\"advisory\":\"GHSA-gone\",\"package\":\"removed-lib\",\"symbols\":[\"*\"],\"complete\":false,\"source\":\"src\\u001b[31m text\"}]}");

        (int code, string output, string error) = Run(Check());

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("evil.json", error);
    }

    [Fact]
    public void In_an_initialized_project_the_check_is_audited_and_the_log_still_verifies()
    {
        Assert.Equal((int)ExitCode.Success, Run("init", _root).Code);
        Assert.Equal((int)ExitCode.Success, Run(Check()).Code);

        string last = File.ReadAllLines(Path.Combine(_root, ".deprisk", "audit.log"))[^1];
        Assert.Contains("symbols-check", last);
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);
    }

    [Fact]
    public void Wrong_use_is_an_input_error()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run("symbols", "check", _root, "--symbols", Symbols).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("symbols", "check", _root, "--advisories", Osv).Code);

        (int gate, _, string gateError) = Run(Check("--fail-on", "bogus"));
        Assert.Equal((int)ExitCode.InvalidInput, gate);
        Assert.Contains("is not a condition of 'symbols check'", gateError);

        (int option, _, string optionError) = Run(Check("--bogus"));
        Assert.Equal((int)ExitCode.InvalidInput, option);
        Assert.Contains("unknown option '--bogus' for 'symbols check'", optionError);

        Assert.Equal((int)ExitCode.InvalidInput, Run(Check("another-path")).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run(Check("--format", "json")).Code);
    }

    [Fact]
    public void The_command_is_in_the_usage_text()
    {
        (_, string output, _) = Run("--help");

        Assert.Contains("symbols check [path]", output);
    }
}

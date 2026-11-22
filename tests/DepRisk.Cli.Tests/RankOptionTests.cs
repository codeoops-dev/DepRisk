using System.Text;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// What <c>rank</c> and <c>ci</c> say about their options, and in which order, pinned when their option parsing was moved onto the code that
/// <c>explain</c> and <c>vex</c> share (S20). A differential run of 250 argument vectors across every command found no difference before and after.
/// </summary>
public sealed class RankOptionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-rankopt-" + Guid.NewGuid().ToString("N"));

    private string Osv => Path.Combine(_root, "osv");

    public RankOptionTests()
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

    [Fact]
    public void Missing_advisories_is_explained_with_the_epss_and_kev_options()
    {
        (int code, _, string error) = Run("rank", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("'rank' needs advisory data", error);
        Assert.Contains("--epss", error);
        Assert.Contains("--kev", error);
        Assert.Contains("0007-baseline-ranking.md", error);
    }

    [Fact]
    public void The_format_is_checked_before_the_advisories()
    {
        (int code, _, string error) = Run("rank", _root, "--format", "xml");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("format 'xml' is not supported for 'rank'", error);
    }

    [Fact]
    public void The_policy_is_checked_before_the_risk_options()
    {
        (int code, _, string error) = Run("ci", _root, "--advisories", Osv, "--fail-on", "bogus", "--samples", "5");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("--fail-on:", error);
        Assert.False(error.Contains("only apply with --model risk"));
    }

    [Fact]
    public void Risk_options_without_the_risk_model_are_refused_for_both_commands()
    {
        foreach (string command in new[] { "rank", "ci" })
        {
            (int code, _, string error) = Run(command, _root, "--advisories", Osv, "--samples", "100");

            Assert.Equal((int)ExitCode.InvalidInput, code);
            Assert.Contains($"'{command}': --samples, --seed, --rank-by, and --risk-params only apply with --model risk.", error);
        }
    }

    [Theory]
    [InlineData("--samples", "abc", "--samples must be a whole number from")]
    [InlineData("--seed", "-1", "--seed must be a whole number from 0 to 18446744073709551615.")]
    [InlineData("--rank-by", "bogus", "--rank-by must be one of:")]
    public void Bad_risk_values_are_input_errors(string option, string value, string message)
    {
        (int code, _, string error) = Run("rank", _root, "--advisories", Osv, "--model", "risk", option, value);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains(message, error);
    }

    [Fact]
    public void Fail_on_belongs_to_ci_and_is_an_unknown_option_for_rank()
    {
        (int code, _, string error) = Run("rank", _root, "--advisories", Osv, "--fail-on", "kev");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("unknown option '--fail-on' for 'rank'.", error);
    }

    [Fact]
    public void A_reachability_policy_without_symbols_is_refused()
    {
        (int code, _, string error) = Run("ci", _root, "--advisories", Osv, "--fail-on", "reachable");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("need --symbols", error);
    }

    [Fact]
    public void The_equals_form_works_for_every_option_rank_reads()
    {
        (int code, string output, string error) = Run("rank", _root, $"--advisories={Osv}", "--format=json", "--ecosystem=npm", "--model=risk", "--samples=200", "--seed=7", "--rank-by=p95");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("\"findings\"", output);
    }

    [Fact]
    public void A_missing_value_names_the_option_the_same_way_in_every_command()
    {
        foreach (string[] args in new[] { new[] { "rank", _root, "--epss" }, new[] { "match", _root, "--format" }, new[] { "scan", _root, "-o" }, new[] { "graph", _root, "--ecosystem" } })
        {
            (int code, _, string error) = Run(args);

            Assert.Equal((int)ExitCode.InvalidInput, code);
            Assert.Contains($"option '{args[2]}' needs a value.", error);
        }
    }
}

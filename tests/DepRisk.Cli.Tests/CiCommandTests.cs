using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class CiCommandTests : IDisposable
{
    private const string SampleAssets = """
    {
      "version": 3,
      "targets": {
        "net10.0": {
          "Pkg.One/1.0.0": { "type": "package", "dependencies": { "Pkg.Two": "2.0.0" } },
          "Pkg.Two/2.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net10.0": ["Pkg.One >= 1.0.0"] },
      "project": { "restore": { "projectName": "Sample", "projectPath": "/somewhere/else/Sample.csproj" } }
    }
    """;

    private const string Critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    private const string Medium = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-ci-" + Guid.NewGuid().ToString("N"));

    public CiCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src", "Sample", "obj"));
        File.WriteAllText(Path.Combine(_root, "src", "Sample", "obj", "project.assets.json"), SampleAssets);
        Directory.CreateDirectory(AdvisoryDir);

        // Pkg.One: critical (9.8), no exploitation signal, direct, fixable.
        // Pkg.Two: medium (5.3), in KEV, transitive, no fixed version.
        WriteAdvisory("a.json", Advisory("GHSA-aaa", "CVE-2025-0001", "Pkg.One", Critical, "CRITICAL", "99.0.0"));
        WriteAdvisory("b.json", Advisory("GHSA-bbb", "CVE-2025-0002", "Pkg.Two", Medium, "MODERATE", null));
        File.WriteAllText(KevPath, """{ "catalogVersion": "k1", "vulnerabilities": [ { "cveID": "CVE-2025-0002", "dateAdded": "2026-01-01" } ] }""");
        File.WriteAllText(EpssPath, "cve,epss,percentile\nCVE-2025-0001,0.01,0.2\nCVE-2025-0002,0.40,0.9\n");
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string AdvisoryDir => Path.Combine(_root, "osv");

    private string KevPath => Path.Combine(_root, "kev.json");

    private string EpssPath => Path.Combine(_root, "epss.csv");

    private string LogPath => Path.Combine(_root, ".deprisk", "audit.log");

    private static string Advisory(string id, string cve, string package, string vector, string severity, string? fixedIn)
    {
        string events = fixedIn is null
            ? "{ \"introduced\": \"0\" }"
            : $"{{ \"introduced\": \"0\" }}, {{ \"fixed\": \"{fixedIn}\" }}";

        return $$"""
            {
              "id": "{{id}}", "aliases": ["{{cve}}"], "summary": "Summary of {{id}}",
              "severity": [ { "type": "CVSS_V3", "score": "{{vector}}" } ],
              "database_specific": { "severity": "{{severity}}" },
              "affected": [ { "package": { "ecosystem": "NuGet", "name": "{{package}}" },
                "ranges": [ { "type": "ECOSYSTEM", "events": [ {{events}} ] } ] } ]
            }
            """;
    }

    private void WriteAdvisory(string name, string content) => File.WriteAllText(Path.Combine(AdvisoryDir, name), content);

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private (int Code, string Out, string Err) Ci(params string[] extra)
    {
        List<string> args = ["ci", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath];
        args.AddRange(extra);
        return Run(args.ToArray());
    }

    [Fact]
    public void Without_a_policy_ci_reports_and_exits_zero_with_a_note_on_the_error_stream()
    {
        (int code, string output, string error) = Ci();

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("findings: 2", output);
        Assert.Contains("no policy set (--fail-on)", error);
    }

    [Fact]
    public void A_matching_policy_fails_the_gate_with_exit_code_1_and_lists_the_findings()
    {
        (int code, string output, string error) = Ci("--fail-on", "kev");

        Assert.Equal((int)ExitCode.PolicyGateFailed, code);
        Assert.Contains("findings: 2", output);
        Assert.Contains("policy gate FAILED ('kev'): 1 of 2 finding(s) match", error);
        Assert.Contains("#1 GHSA-bbb", error);
        Assert.DoesNotContain("GHSA-aaa", error);
    }

    [Fact]
    public void A_policy_nothing_matches_passes()
    {
        (int code, _, string error) = Ci("--fail-on", "ransomware");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("policy gate PASSED ('ransomware'): none of 2 finding(s) match", error);
    }

    [Theory]
    [InlineData("cvss>=9", 1)]
    [InlineData("kev&fixable", 0)]
    [InlineData("kev,cvss>=9", 1)]
    [InlineData("direct&fixable", 1)]
    [InlineData("severity>=moderate", 1)]
    [InlineData("epss>=0.3", 1)]
    [InlineData("any", 1)]
    public void The_gate_result_follows_the_expression(string policy, int expectedExitCode)
    {
        Assert.Equal(expectedExitCode, Ci("--fail-on", policy).Code);
    }

    [Fact]
    public void With_json_or_sarif_on_standard_output_the_verdict_stays_on_the_error_stream()
    {
        (int jsonCode, string json, string jsonError) = Ci("--fail-on", "kev", "--format", "json");
        (int sarifCode, string sarif, string sarifError) = Ci("--fail-on", "kev", "--format", "sarif");

        Assert.Equal((int)ExitCode.PolicyGateFailed, jsonCode);
        Assert.Equal((int)ExitCode.PolicyGateFailed, sarifCode);
        Assert.Contains("FAILED", jsonError);
        Assert.Contains("FAILED", sarifError);

        using JsonDocument jsonDocument = JsonDocument.Parse(json);
        Assert.Equal(1, jsonDocument.RootElement.GetProperty("schemaVersion").GetInt32());
        using JsonDocument sarifDocument = JsonDocument.Parse(sarif);
        Assert.Equal("2.1.0", sarifDocument.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public void Sarif_results_point_at_the_repository_project_file_not_at_the_machine_path()
    {
        (_, string sarif, _) = Ci("--format", "sarif");

        using JsonDocument document = JsonDocument.Parse(sarif);
        string uri = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString()!;

        Assert.Equal("src/Sample/Sample.csproj", uri);
        Assert.DoesNotContain("somewhere", sarif);
    }

    [Fact]
    public void Out_writes_the_file_even_when_the_gate_fails()
    {
        string target = Path.Combine(_root, "deprisk.sarif");

        (int code, string output, string error) = Ci("--fail-on", "kev", "--format", "sarif", "--out", target);

        Assert.Equal((int)ExitCode.PolicyGateFailed, code);
        Assert.Contains("Wrote sarif ranking", output);
        Assert.Contains("FAILED", error);
        Assert.Contains("\"version\": \"2.1.0\"", File.ReadAllText(target));
    }

    [Fact]
    public void Invalid_or_unavailable_policy_terms_are_input_errors_and_nothing_is_run()
    {
        (int badCode, string badOutput, string badError) = Ci("--fail-on", "cvss>=11");
        (int reachableCode, _, string reachableError) = Ci("--fail-on", "reachable");

        Assert.Equal((int)ExitCode.InvalidInput, badCode);
        Assert.Equal(string.Empty, badOutput);
        Assert.Contains("--fail-on", badError);
        Assert.Equal((int)ExitCode.InvalidInput, reachableCode);
        Assert.Contains("not available yet", reachableError);
        Assert.Equal((int)ExitCode.InvalidInput, Ci("--fail-on").Code);
    }

    [Fact]
    public void Advisory_data_is_required_and_ci_names_itself_in_the_message()
    {
        (int code, _, string error) = Run("ci", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("'ci' needs advisory data", error);
    }

    [Fact]
    public void Output_is_identical_between_runs_whatever_the_verdict()
    {
        (_, string first, _) = Ci("--fail-on", "kev", "--format", "sarif");
        (_, string second, _) = Ci("--fail-on", "kev", "--format", "sarif");

        Assert.Equal(first, second);
    }

    [Fact]
    public void In_an_initialized_project_ci_is_audited_including_the_gate_decision()
    {
        Run("init");

        Ci("--fail-on", "kev", "--format", "json");
        Ci("--fail-on", "ransomware", "--format", "json");

        string[] lines = File.ReadAllLines(LogPath);
        Assert.Equal(3, lines.Length);

        using JsonDocument failed = JsonDocument.Parse(lines[1]);
        using JsonDocument passed = JsonDocument.Parse(lines[2]);
        Assert.Equal("ci", failed.RootElement.GetProperty("command").GetString());

        JsonElement failedGate = failed.RootElement.GetProperty("changes").EnumerateArray().Single(c => c.GetProperty("subject").GetString() == "policy gate");
        Assert.Equal("kev", failedGate.GetProperty("from").GetString());
        Assert.Equal("failed (1 finding(s))", failedGate.GetProperty("to").GetString());

        JsonElement passedGate = passed.RootElement.GetProperty("changes").EnumerateArray().Single(c => c.GetProperty("subject").GetString() == "policy gate");
        Assert.Equal("passed", passedGate.GetProperty("to").GetString());

        Assert.Equal((int)ExitCode.Success, Run("audit", "verify").Code);
    }

    [Fact]
    public void More_than_ten_tripped_findings_are_summarized()
    {
        for (int i = 0; i < 12; i++)
        {
            WriteAdvisory($"many-{i:D2}.json", Advisory($"GHSA-m{i:D2}", $"CVE-2025-1{i:D3}", "Pkg.One", Critical, "CRITICAL", "99.0.0"));
        }

        (int code, _, string error) = Ci("--fail-on", "any");

        Assert.Equal((int)ExitCode.PolicyGateFailed, code);
        Assert.Contains("... and 4 more", error);
    }

    [Fact]
    public void The_policy_text_in_the_verdict_is_cleaned_of_control_characters()
    {
        (_, _, string error) = Ci("--fail-on", "kev\u001b[31m,any");

        // An invalid term makes the whole expression an input error, and the message must not echo raw control characters.
        Assert.False(error.Contains('\u001b'), "no ESC on the error stream");
    }
}

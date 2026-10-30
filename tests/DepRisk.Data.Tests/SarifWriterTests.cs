using System.Text.Json;
using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Data.Sarif;
using Xunit;

namespace DepRisk.Data.Tests;

public class SarifWriterTests
{
    private static readonly ToolInfo Tool = new("deprisk", "0.1.0-test");

    private const string Vector98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    private static RankedFinding Ranked(
        int rank,
        string id,
        string package = "Pkg",
        string? severity = null,
        string? summary = "A summary",
        double? cvss = null,
        bool kev = false,
        double? epss = null,
        string[]? fixedVersions = null,
        params FindingLocation[] locations) =>
        new(
            rank,
            id,
            ["CVE-2025-0001"],
            summary,
            severity,
            new FindingPackage(package, "1.0.0"),
            fixedVersions ?? ["2.0.0"],
            locations.Length == 0 ? [new FindingLocation("App", "net10.0", true, "src/App/App.csproj")] : locations,
            new FindingSignals(
                cvss is null ? null : new CvssSignal("3.1", Vector98, cvss.Value, "HIGH"),
                epss is null ? null : new EpssSignal("CVE-2025-0001", epss.Value, 0.5),
                kev ? new KevSignal("CVE-2025-0001", "2025-01-01", false) : null));

    private static RankingResult Result(params RankedFinding[] findings) =>
        new(
            1,
            Tool,
            "nuget",
            RankingResult.BaselineMethod,
            RankingResult.BaselineOrdering,
            new AdvisorySourceInfo("osv", new string('a', 64), 1, 0, 0, 0),
            new SignalSources(null, null),
            1,
            1,
            0,
            findings);

    private static JsonDocument Parse(RankingResult result) => JsonDocument.Parse(SarifWriter.Serialize(result));

    [Fact]
    public void The_document_has_the_sarif_envelope_and_tool_information()
    {
        using JsonDocument document = Parse(Result(Ranked(1, "A-1")));
        JsonElement root = document.RootElement;

        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        Assert.Equal(SarifWriter.SchemaUri, root.GetProperty("$schema").GetString());

        JsonElement driver = Assert.Single(root.GetProperty("runs").EnumerateArray().ToArray()).GetProperty("tool").GetProperty("driver");
        Assert.Equal("DepRisk", driver.GetProperty("name").GetString());
        Assert.Equal("0.1.0-test", driver.GetProperty("semanticVersion").GetString());
        Assert.StartsWith("https://", driver.GetProperty("informationUri").GetString());
    }

    [Fact]
    public void There_is_one_rule_per_advisory_sorted_and_results_point_at_them_by_index()
    {
        RankingResult result = Result(
            Ranked(1, "B-2", package: "One"),
            Ranked(2, "A-1", package: "One"),
            Ranked(3, "A-1", package: "Two"));

        using JsonDocument document = Parse(result);
        JsonElement run = document.RootElement.GetProperty("runs")[0];
        JsonElement rules = run.GetProperty("tool").GetProperty("driver").GetProperty("rules");

        Assert.Equal(new[] { "A-1", "B-2" }, rules.EnumerateArray().Select(r => r.GetProperty("id").GetString()).ToArray());

        JsonElement[] results = run.GetProperty("results").EnumerateArray().ToArray();
        Assert.Equal(new[] { "B-2", "A-1", "A-1" }, results.Select(r => r.GetProperty("ruleId").GetString()).ToArray());
        Assert.Equal(new[] { 1, 0, 0 }, results.Select(r => r.GetProperty("ruleIndex").GetInt32()).ToArray());
        Assert.Equal(new[] { 1, 2, 3 }, results.Select(r => r.GetProperty("properties").GetProperty("rank").GetInt32()).ToArray());
    }

    [Theory]
    [InlineData(null, null, false, "warning")]
    [InlineData("CRITICAL", null, false, "error")]
    [InlineData("HIGH", null, false, "error")]
    [InlineData("MODERATE", null, false, "warning")]
    [InlineData("MEDIUM", null, false, "warning")]
    [InlineData("LOW", null, false, "note")]
    [InlineData("LOW", null, true, "error")]
    [InlineData(null, 9.8, false, "warning")]
    public void Levels_follow_kev_then_the_cvss_rating_then_the_database_severity(string? severity, double? cvss, bool kev, string expected)
    {
        // The test builds a CVSS signal with rating "HIGH" whenever a score is given; see the dedicated test below for ratings.
        RankedFinding finding = Ranked(1, "A-1", severity: severity, cvss: cvss, kev: kev);

        string level = SarifWriter.LevelFor(cvss is null ? finding : finding with { Signals = finding.Signals with { Cvss = new CvssSignal("3.1", Vector98, cvss.Value, "MEDIUM") } });

        Assert.Equal(expected, level);
    }

    [Theory]
    [InlineData("CRITICAL", "error")]
    [InlineData("HIGH", "error")]
    [InlineData("MEDIUM", "warning")]
    [InlineData("LOW", "note")]
    [InlineData("NONE", "note")]
    public void The_cvss_rating_wins_over_the_database_severity(string rating, string expected)
    {
        RankedFinding finding = Ranked(1, "A-1", severity: "CRITICAL", cvss: 5.0);
        finding = finding with { Signals = finding.Signals with { Cvss = new CvssSignal("3.1", Vector98, 5.0, rating) } };

        Assert.Equal(expected, SarifWriter.LevelFor(finding));
    }

    [Fact]
    public void Rules_carry_the_security_severity_help_and_tags()
    {
        using JsonDocument document = Parse(Result(Ranked(1, "GHSA-xxxx", cvss: 9.8, kev: true)));
        JsonElement rule = document.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0];

        Assert.Equal("9.8", rule.GetProperty("properties").GetProperty("security-severity").GetString());
        Assert.Contains("known-exploited", rule.GetProperty("properties").GetProperty("tags").EnumerateArray().Select(t => t.GetString()).ToArray());
        Assert.Equal("https://osv.dev/vulnerability/GHSA-xxxx", rule.GetProperty("helpUri").GetString());
        Assert.Contains("Upgrade Pkg to 2.0.0", rule.GetProperty("help").GetProperty("text").GetString());
        Assert.Equal("error", rule.GetProperty("defaultConfiguration").GetProperty("level").GetString());
    }

    [Fact]
    public void Without_a_cvss_score_there_is_no_security_severity_and_without_a_fix_the_help_says_so()
    {
        using JsonDocument document = Parse(Result(Ranked(1, "A-1", fixedVersions: [])));
        JsonElement rule = document.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0];

        Assert.False(rule.GetProperty("properties").TryGetProperty("security-severity", out _));
        Assert.Contains("No fixed version", rule.GetProperty("help").GetProperty("text").GetString());
    }

    [Fact]
    public void The_help_uri_escapes_the_advisory_id()
    {
        using JsonDocument document = Parse(Result(Ranked(1, "A B/../C?x=1")));
        string uri = document.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0]
            .GetProperty("helpUri").GetString()!;

        Assert.Equal("https://osv.dev/vulnerability/A%20B%2F..%2FC%3Fx%3D1", uri);
    }

    [Fact]
    public void Results_are_located_at_the_distinct_project_files_with_escaped_relative_uris()
    {
        RankedFinding finding = Ranked(
            1,
            "A-1",
            locations:
            [
                new FindingLocation("Web", "net10.0", true, "src/My App/Web.csproj"),
                new FindingLocation("Web", "net10.0/linux-x64", true, "src/My App/Web.csproj"),
                new FindingLocation("Api", "net10.0", false, "src\\Api\\Api.csproj"),
            ]);

        using JsonDocument document = Parse(Result(finding));
        JsonElement[] locations = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("locations").EnumerateArray().ToArray();

        Assert.Equal(
            new[] { "src/Api/Api.csproj", "src/My%20App/Web.csproj" },
            locations.Select(l => l.GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString()).ToArray());
        Assert.All(locations, l =>
        {
            Assert.Equal("%SRCROOT%", l.GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uriBaseId").GetString());
            Assert.Equal(1, l.GetProperty("physicalLocation").GetProperty("region").GetProperty("startLine").GetInt32());
        });
    }

    [Fact]
    public void Results_carry_a_stable_fingerprint_and_useful_properties()
    {
        RankedFinding finding = Ranked(1, "A-1", package: "My.Pkg", cvss: 9.8, kev: true, epss: 0.41);

        using JsonDocument first = Parse(Result(finding));
        using JsonDocument second = Parse(Result(finding with { Rank = 7 }));
        JsonElement a = first.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
        JsonElement b = second.RootElement.GetProperty("runs")[0].GetProperty("results")[0];

        string fingerprint = a.GetProperty("partialFingerprints").GetProperty("deprisk/v1").GetString()!;
        Assert.Equal(64, fingerprint.Length);
        Assert.Equal(fingerprint, b.GetProperty("partialFingerprints").GetProperty("deprisk/v1").GetString());

        JsonElement properties = a.GetProperty("properties");
        Assert.Equal("My.Pkg", properties.GetProperty("package").GetProperty("id").GetString());
        Assert.True(properties.GetProperty("kev").GetBoolean());
        Assert.True(properties.GetProperty("direct").GetBoolean());
        Assert.Equal(0.41, properties.GetProperty("epss").GetDouble());
        Assert.Equal(9.8, properties.GetProperty("cvss").GetDouble());
        Assert.Equal("2.0.0", properties.GetProperty("fixedVersions")[0].GetString());
    }

    [Fact]
    public void Different_packages_or_versions_get_different_fingerprints()
    {
        using JsonDocument document = Parse(Result(Ranked(1, "A-1", package: "One"), Ranked(2, "A-1", package: "Two")));
        JsonElement[] results = document.RootElement.GetProperty("runs")[0].GetProperty("results").EnumerateArray().ToArray();

        Assert.NotEqual(
            results[0].GetProperty("partialFingerprints").GetProperty("deprisk/v1").GetString(),
            results[1].GetProperty("partialFingerprints").GetProperty("deprisk/v1").GetString());
    }

    [Fact]
    public void The_message_states_package_advisory_fix_signals_and_rank()
    {
        using JsonDocument document = Parse(Result(Ranked(3, "A-1", package: "My.Pkg", summary: "Bad things.", cvss: 9.8, kev: true, epss: 0.5)));
        string message = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("message").GetProperty("text").GetString()!;

        Assert.Contains("My.Pkg 1.0.0 is affected by A-1.", message);
        Assert.Contains("Bad things.", message);
        Assert.Contains("Fixed in 2.0.0.", message);
        Assert.Contains("CISA KEV", message);
        Assert.Contains("EPSS 0.500.", message);
        Assert.Contains("CVSS 9.8", message);
        Assert.Contains("Priority rank 3.", message);
    }

    [Fact]
    public void Control_characters_in_advisory_text_never_reach_the_document()
    {
        RankedFinding evil = Ranked(1, "A-1", summary: "\u001b[2JHACKED\u0007 text\nsecond line");

        string sarif = SarifWriter.Serialize(Result(evil));

        Assert.False(sarif.Contains('\u001b'));
        Assert.False(sarif.Contains('\u0007'));
        using JsonDocument document = JsonDocument.Parse(sarif);
        string message = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("message").GetProperty("text").GetString()!;
        Assert.False(message.Any(char.IsControl));
        Assert.Contains("HACKED", message);
    }

    [Fact]
    public void A_very_long_summary_is_bounded_in_the_message()
    {
        using JsonDocument document = Parse(Result(Ranked(1, "A-1", summary: new string('x', 5000))));
        string message = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("message").GetProperty("text").GetString()!;

        Assert.True(message.Length <= 601);
    }

    [Fact]
    public void No_findings_still_gives_a_valid_empty_run()
    {
        using JsonDocument document = Parse(Result());
        JsonElement run = document.RootElement.GetProperty("runs")[0];

        Assert.Equal(0, run.GetProperty("results").GetArrayLength());
        Assert.Equal(0, run.GetProperty("tool").GetProperty("driver").GetProperty("rules").GetArrayLength());
    }

    [Fact]
    public void The_run_records_the_method_and_data_digests_but_no_time_or_machine_paths()
    {
        string sarif = SarifWriter.Serialize(Result(Ranked(1, "A-1")));

        using JsonDocument document = JsonDocument.Parse(sarif);
        JsonElement properties = document.RootElement.GetProperty("runs")[0].GetProperty("properties").GetProperty("deprisk");

        Assert.Equal("baseline-kev-epss-cvss", properties.GetProperty("method").GetString());
        Assert.Equal(new string('a', 64), properties.GetProperty("advisoriesDigest").GetString());
        Assert.Equal(JsonValueKind.Null, properties.GetProperty("epssDigest").ValueKind);
        Assert.DoesNotContain("startTimeUtc", sarif);
        Assert.DoesNotContain("endTimeUtc", sarif);
        Assert.DoesNotContain("\r", sarif);
    }

    [Fact]
    public void Output_is_byte_for_byte_stable()
    {
        RankingResult result = Result(Ranked(1, "A-1", cvss: 9.8), Ranked(2, "B-2"));

        Assert.Equal(SarifWriter.Serialize(result), SarifWriter.Serialize(result));
    }

    [Theory]
    [InlineData("src/App/App.csproj", "src/App/App.csproj")]
    [InlineData("src\\App\\App.csproj", "src/App/App.csproj")]
    [InlineData("my app/a#b.csproj", "my%20app/a%23b.csproj")]
    [InlineData("App.csproj", "App.csproj")]
    public void Paths_are_escaped_segment_by_segment(string path, string expected)
    {
        Assert.Equal(expected, SarifWriter.EscapePath(path));
    }
}

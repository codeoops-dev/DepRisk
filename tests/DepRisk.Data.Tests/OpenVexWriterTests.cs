using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.OpenVex;
using Xunit;

namespace DepRisk.Data.Tests;

public class OpenVexWriterTests
{
    private static readonly ToolInfo Tool = new("deprisk", "0.0.0-test");
    private static readonly DateTimeOffset At = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);

    private static OpenVexOptions Options(DateTimeOffset? at = null, string? role = null, string product = "pkg:nuget/MyApp@1.0.0") =>
        new(product, "Example Team", role, at ?? At, "deprisk 0.0.0-test");

    private static RankedFinding F(
        string id,
        string package = "Pkg",
        string version = "1.0.0",
        string[]? aliases = null,
        string[]? fixedIn = null,
        string? label = null,
        string reason = "static-path",
        string? symbol = null,
        bool direct = true) =>
        new(
            1,
            id,
            aliases ?? [],
            $"summary of {id}",
            null,
            new FindingPackage(package, version),
            fixedIn ?? [],
            [new FindingLocation("App", "net10.0", direct)],
            new FindingSignals(null, null, null),
            label is null ? null : new FindingReach(label, reason, symbol));

    private static RankingResult Ranking(string ecosystem, params RankedFinding[] findings) =>
        new(
            1,
            Tool,
            ecosystem,
            RankingResult.BaselineMethod,
            RankingResult.BaselineOrdering,
            new AdvisorySourceInfo("osv", new string('a', 64), findings.Length, 0, 0, 0),
            new SignalSources(null, null),
            1,
            findings.Length,
            0,
            findings);

    private static ReachabilityResult Reach(params RankedFinding[] findings) =>
        new(
            1,
            Tool,
            "nuget",
            new AdvisorySourceInfo("osv", new string('a', 64), findings.Length, 0, 0, 0),
            new SymbolMapInfo("maps", new string('b', 64), 1, 1),
            new ReachAnalyzerInfo("deprisk-reach", "1.2.3", new string('c', 64)),
            new ReachSourceInfo(new string('d', 64), 10, 0, 0, 5, 5, 1),
            new ReachSummary(0, 0, 0, 0),
            findings
                .Select(f => new ReachFinding(
                    new Finding(f.Id, f.Aliases, f.Summary, f.Severity, [], f.Package, f.FixedVersions, f.Locations),
                    new ReachVerdict(f.Reachability!.Label, f.Reachability.Reason, f.Reachability.Symbol, [], ["curated"])))
                .ToList(),
            []);

    private static JsonDocument Write(RankingResult ranking, ReachabilityResult? reach, OpenVexOptions? options = null) =>
        JsonDocument.Parse(OpenVexWriter.Serialize(ranking, reach, options ?? Options()));

    [Fact]
    public void The_document_has_the_openvex_header()
    {
        using JsonDocument document = Write(Ranking("nuget", F("GHSA-1")), null, Options(role: "Security Team"));
        JsonElement root = document.RootElement;

        Assert.Equal("https://openvex.dev/ns/v0.2.0", root.GetProperty("@context").GetString());
        Assert.StartsWith("urn:deprisk:vex:sha256:", root.GetProperty("@id").GetString());
        Assert.Equal("Example Team", root.GetProperty("author").GetString());
        Assert.Equal("Security Team", root.GetProperty("role").GetString());
        Assert.Equal("2026-11-05T12:00:00Z", root.GetProperty("timestamp").GetString());
        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.Equal("deprisk 0.0.0-test", root.GetProperty("tooling").GetString());
    }

    [Fact]
    public void The_role_is_left_out_when_not_given_and_the_timestamp_is_utc_to_the_second()
    {
        using JsonDocument document = Write(Ranking("nuget", F("GHSA-1")), null, Options(at: new DateTimeOffset(2026, 11, 5, 15, 30, 7, 123, TimeSpan.FromHours(3.5))));

        Assert.False(document.RootElement.TryGetProperty("role", out _));
        Assert.Equal("2026-11-05T12:00:07Z", document.RootElement.GetProperty("timestamp").GetString());
    }

    [Fact]
    public void Each_status_carries_what_openvex_requires_of_it()
    {
        RankedFinding unreachable = F("GHSA-1", label: "unreachable", reason: "no-path");
        RankedFinding reachable = F("GHSA-2", fixedIn: ["2.0.0"], label: "reachable", symbol: "A.B.C");
        RankedFinding possible = F("GHSA-3", label: "possibly-reachable", reason: "dynamic-path");
        RankedFinding plain = F("GHSA-4");
        RankingResult ranking = Ranking("nuget", unreachable, reachable, possible, plain);

        using JsonDocument document = Write(ranking, Reach(unreachable, reachable, possible));
        JsonElement[] statements = document.RootElement.GetProperty("statements").EnumerateArray().ToArray();

        JsonElement notAffected = statements[0];
        Assert.Equal("not_affected", notAffected.GetProperty("status").GetString());
        Assert.Equal("vulnerable_code_not_in_execute_path", notAffected.GetProperty("justification").GetString());
        Assert.True(notAffected.TryGetProperty("impact_statement", out _));
        Assert.False(notAffected.TryGetProperty("action_statement", out _));

        JsonElement affected = statements[1];
        Assert.Equal("affected", affected.GetProperty("status").GetString());
        Assert.Equal("Upgrade Pkg to 2.0.0 or later.", affected.GetProperty("action_statement").GetString());   // required by the spec for "affected"

        JsonElement investigating = statements[2];
        Assert.Equal("under_investigation", investigating.GetProperty("status").GetString());
        Assert.True(investigating.TryGetProperty("status_notes", out _));
        Assert.False(investigating.TryGetProperty("justification", out _));

        Assert.Equal("under_investigation", statements[3].GetProperty("status").GetString());
    }

    [Fact]
    public void A_statement_names_the_vulnerability_the_product_and_the_vulnerable_package_as_a_subcomponent()
    {
        using JsonDocument document = Write(
            Ranking("nuget", F("GHSA-1", "Newtonsoft.Json", "12.0.1", aliases: ["CVE-2099-2", "CVE-2099-1", "CVE-2099-1"])),
            null);

        JsonElement statement = document.RootElement.GetProperty("statements")[0];
        JsonElement vulnerability = statement.GetProperty("vulnerability");

        Assert.Equal("GHSA-1", vulnerability.GetProperty("name").GetString());
        Assert.Equal("https://osv.dev/vulnerability/GHSA-1", vulnerability.GetProperty("@id").GetString());
        Assert.Equal("summary of GHSA-1", vulnerability.GetProperty("description").GetString());
        Assert.Equal(new[] { "CVE-2099-1", "CVE-2099-2" }, vulnerability.GetProperty("aliases").EnumerateArray().Select(a => a.GetString()!).ToArray());

        JsonElement product = statement.GetProperty("products")[0];
        Assert.Equal("pkg:nuget/MyApp@1.0.0", product.GetProperty("@id").GetString());
        Assert.Equal("pkg:nuget/Newtonsoft.Json@12.0.1", product.GetProperty("subcomponents")[0].GetProperty("@id").GetString());
    }

    [Theory]
    [InlineData("nuget", "Newtonsoft.Json", "12.0.1", "pkg:nuget/Newtonsoft.Json@12.0.1")]
    [InlineData("nuget", "Pkg", "1.0.0-beta.1", "pkg:nuget/Pkg@1.0.0-beta.1")]
    [InlineData("npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21")]
    [InlineData("npm", "@babel/code-frame", "7.24.0", "pkg:npm/%40babel/code-frame@7.24.0")]
    [InlineData("npm", "pkg", "1.0.0+build.5", "pkg:npm/pkg@1.0.0%2Bbuild.5")]
    public void Package_urls_follow_the_purl_rules(string ecosystem, string id, string version, string expected)
    {
        Assert.Equal(expected, OpenVexWriter.PackageUrl(ecosystem, id, version));
    }

    [Fact]
    public void The_same_inputs_give_the_same_document_and_any_change_gives_a_new_id()
    {
        RankingResult ranking = Ranking("nuget", F("GHSA-1"), F("GHSA-2"));

        string one = OpenVexWriter.Serialize(ranking, null, Options());
        string two = OpenVexWriter.Serialize(ranking, null, Options());
        string later = OpenVexWriter.Serialize(ranking, null, Options(at: At.AddSeconds(1)));
        string otherProduct = OpenVexWriter.Serialize(ranking, null, Options(product: "pkg:nuget/Other@1.0.0"));
        string otherFinding = OpenVexWriter.Serialize(Ranking("nuget", F("GHSA-1"), F("GHSA-3")), null, Options());

        string Id(string json) => JsonDocument.Parse(json).RootElement.GetProperty("@id").GetString()!;

        Assert.Equal(one, two);
        Assert.NotEqual(Id(one), Id(later));
        Assert.NotEqual(Id(one), Id(otherProduct));
        Assert.NotEqual(Id(one), Id(otherFinding));
    }

    [Fact]
    public void Statements_are_ordered_by_advisory_package_and_version_whatever_the_input_order()
    {
        RankingResult ranking = Ranking("nuget", F("GHSA-2", "B"), F("GHSA-1", "B", "2.0.0"), F("GHSA-1", "A"), F("GHSA-1", "B", "1.0.0"));

        using JsonDocument document = Write(ranking, null);
        string[] order = document.RootElement.GetProperty("statements").EnumerateArray()
            .Select(s => s.GetProperty("vulnerability").GetProperty("name").GetString() + " " + s.GetProperty("products")[0].GetProperty("subcomponents")[0].GetProperty("@id").GetString())
            .ToArray();

        Assert.Equal(
            new[] { "GHSA-1 pkg:nuget/A@1.0.0", "GHSA-1 pkg:nuget/B@1.0.0", "GHSA-1 pkg:nuget/B@2.0.0", "GHSA-2 pkg:nuget/B@1.0.0" },
            order);
    }

    [Fact]
    public void An_empty_ranking_is_a_valid_document_without_statements()
    {
        using JsonDocument document = Write(Ranking("nuget"), null);

        Assert.Equal(0, document.RootElement.GetProperty("statements").GetArrayLength());
    }

    [Fact]
    public void Text_from_advisories_is_escaped_as_json_not_executed_or_truncated()
    {
        RankedFinding finding = F("GHSA-1/..\"x") with { Summary = "line one\nline \"two\" <b>" };

        string json = OpenVexWriter.Serialize(Ranking("nuget", finding), null, Options());
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement vulnerability = document.RootElement.GetProperty("statements")[0].GetProperty("vulnerability");

        Assert.Equal("line one\nline \"two\" <b>", vulnerability.GetProperty("description").GetString());
        Assert.Equal("https://osv.dev/vulnerability/GHSA-1%2F..%22x", vulnerability.GetProperty("@id").GetString());
    }
}

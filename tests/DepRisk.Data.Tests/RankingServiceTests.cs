using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Core.Signals;
using DepRisk.Data.Osv;
using Xunit;

namespace DepRisk.Data.Tests;

public class RankingServiceTests
{
    private static readonly ToolInfo Tool = new("deprisk", "0.0.0-test");

    private static Finding Finding(string id, string package, string[] aliases) =>
        new(id, aliases, "summary", "HIGH", [new AdvisorySeverity("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")],
            new FindingPackage(package, "1.0.0"), ["2.0.0"], [new FindingLocation("App", "net10.0", true)]);

    private static FindingsResult Findings(params Finding[] findings) =>
        new(
            1,
            Tool,
            "nuget",
            new AdvisorySourceInfo("osv", new string('a', 64), 3, 0, 0, 0),
            1,
            2,
            0,
            findings);

    [Fact]
    public void Compute_ranks_and_describes_the_sources_without_times_or_paths()
    {
        FindingsResult findings = Findings(
            Finding("GHSA-1", "One", ["CVE-2025-0001"]),
            Finding("GHSA-2", "Two", ["CVE-2025-0002"]));

        EpssData epss = new(
            new Dictionary<string, EpssScore> { ["CVE-2025-0001"] = new(0.9, 0.99), ["CVE-2025-0002"] = new(0.1, 0.5) },
            "v2025.03.14",
            "2026-10-20",
            "epss.csv.gz",
            new string('c', 64),
            2,
            []);

        KevData kev = new(
            new Dictionary<string, KevEntry> { ["CVE-2025-0002"] = new("CVE-2025-0002", "2025-01-01", true) },
            "2026.10.20",
            "2026-10-20",
            "kev.json",
            new string('d', 64),
            1,
            []);

        RankingResult result = RankingService.Compute(findings, epss, kev, Tool);

        Assert.Equal(new[] { "GHSA-2", "GHSA-1" }, result.Findings.Select(f => f.Id).ToArray());
        Assert.Equal(RankingResult.BaselineMethod, result.Method);
        Assert.Equal(new[] { "kev", "epss", "cvss", "severity", "id" }, result.Ordering.ToArray());

        Assert.Equal("epss.csv.gz", result.Signals.Epss!.Source);
        Assert.Equal("v2025.03.14", result.Signals.Epss.Version);
        Assert.Equal(2, result.Signals.Epss.Entries);
        Assert.Equal(2, result.Signals.Epss.Skipped);
        Assert.Equal("2026.10.20", result.Signals.Kev!.Version);
        Assert.Equal(1, result.Signals.Kev.Entries);
        Assert.Equal(1, result.Signals.Kev.Skipped);

        Assert.True(result.Findings[0].Signals.Kev!.KnownRansomwareUse);
        Assert.Equal(9.8, result.Findings[1].Signals.Cvss!.BaseScore);
        Assert.Equal(0.9, result.Findings[1].Signals.Epss!.Probability);
    }

    [Fact]
    public void Without_epss_and_kev_the_sources_are_null_and_cvss_still_orders()
    {
        RankingResult result = RankingService.Compute(Findings(Finding("GHSA-1", "One", [])), null, null, Tool);

        Assert.Null(result.Signals.Epss);
        Assert.Null(result.Signals.Kev);
        Assert.Equal(1, Assert.Single(result.Findings).Rank);
    }

    [Fact]
    public void The_json_has_the_documented_shape_and_is_byte_stable()
    {
        FindingsResult findings = Findings(Finding("GHSA-1", "One", ["CVE-2025-0001"]));
        RankingResult first = RankingService.Compute(findings, null, null, Tool);
        RankingResult second = RankingService.Compute(findings, null, null, Tool);

        string json = RankingResultJson.Serialize(first);

        Assert.Equal(json, RankingResultJson.Serialize(second));
        Assert.DoesNotContain("\r", json);

        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(json);
        System.Text.Json.JsonElement root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("baseline-kev-epss-cvss", root.GetProperty("method").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, root.GetProperty("signals").GetProperty("epss").ValueKind);

        System.Text.Json.JsonElement finding = root.GetProperty("findings")[0];
        Assert.Equal(1, finding.GetProperty("rank").GetInt32());
        Assert.Equal(9.8, finding.GetProperty("signals").GetProperty("cvss").GetProperty("baseScore").GetDouble());
        Assert.Equal("CRITICAL", finding.GetProperty("signals").GetProperty("cvss").GetProperty("rating").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, finding.GetProperty("signals").GetProperty("kev").ValueKind);
    }
}

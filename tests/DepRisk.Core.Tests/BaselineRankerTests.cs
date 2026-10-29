using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Core.Ranking;
using DepRisk.Core.Signals;
using Xunit;

namespace DepRisk.Core.Tests;

public class BaselineRankerTests
{
    private const string Critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; // 9.8
    private const string Medium = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"; // 5.3

    private static Finding Finding(
        string id,
        string package = "Pkg",
        string[]? aliases = null,
        string? severity = null,
        string[]? vectors = null) =>
        new(
            id,
            aliases ?? [],
            null,
            severity,
            (vectors ?? []).Select(v => new AdvisorySeverity("CVSS_V3", v)).ToList(),
            new FindingPackage(package, "1.0.0"),
            [],
            [new FindingLocation("App", "net10.0", true)]);

    private static EpssData Epss(params (string Cve, double Probability)[] scores) =>
        new(
            scores.ToDictionary(s => s.Cve, s => new EpssScore(s.Probability, 0.5), StringComparer.Ordinal),
            "v1",
            "2026-01-01",
            "epss.csv",
            new string('a', 64),
            0,
            []);

    private static KevData Kev(params string[] cves) =>
        new(
            cves.ToDictionary(c => c, c => new KevEntry(c, "2025-01-01", false), StringComparer.Ordinal),
            "2026.01.01",
            "2026-01-01",
            "kev.json",
            new string('b', 64),
            0,
            []);

    private static string[] Order(IReadOnlyList<RankedFinding> ranked) => ranked.Select(r => r.Id).ToArray();

    [Fact]
    public void Kev_listed_findings_come_first_even_with_a_lower_score()
    {
        Finding[] findings =
        [
            Finding("A-critical", aliases: ["CVE-2025-0001"], vectors: [Critical]),
            Finding("B-in-kev", aliases: ["CVE-2025-0002"], vectors: [Medium]),
        ];

        IReadOnlyList<RankedFinding> ranked = BaselineRanker.Rank(findings, Epss(("CVE-2025-0001", 0.99)), Kev("CVE-2025-0002"));

        Assert.Equal(new[] { "B-in-kev", "A-critical" }, Order(ranked));
        Assert.Equal(new[] { 1, 2 }, ranked.Select(r => r.Rank).ToArray());
    }

    [Fact]
    public void Epss_orders_findings_that_are_equal_on_kev()
    {
        Finding[] findings =
        [
            Finding("A-low-epss", aliases: ["CVE-2025-0001"], vectors: [Critical]),
            Finding("B-high-epss", aliases: ["CVE-2025-0002"], vectors: [Medium]),
        ];

        IReadOnlyList<RankedFinding> ranked = BaselineRanker.Rank(findings, Epss(("CVE-2025-0001", 0.01), ("CVE-2025-0002", 0.60)), null);

        Assert.Equal(new[] { "B-high-epss", "A-low-epss" }, Order(ranked));
    }

    [Fact]
    public void Cvss_orders_findings_equal_on_kev_and_epss()
    {
        Finding[] findings =
        [
            Finding("A-medium", vectors: [Medium]),
            Finding("B-critical", vectors: [Critical]),
        ];

        Assert.Equal(new[] { "B-critical", "A-medium" }, Order(BaselineRanker.Rank(findings, null, null)));
    }

    [Fact]
    public void The_database_severity_orders_findings_without_a_usable_vector()
    {
        Finding[] findings =
        [
            Finding("A-low", severity: "LOW"),
            Finding("B-critical", severity: "CRITICAL"),
            Finding("C-moderate", severity: "MODERATE"),
            Finding("D-none"),
        ];

        Assert.Equal(new[] { "B-critical", "C-moderate", "A-low", "D-none" }, Order(BaselineRanker.Rank(findings, null, null)));
    }

    [Fact]
    public void Missing_data_sorts_after_present_data_on_the_same_key()
    {
        Finding[] findings =
        [
            Finding("A-no-epss", aliases: ["CVE-2025-0001"]),
            Finding("B-tiny-epss", aliases: ["CVE-2025-0002"]),
        ];

        IReadOnlyList<RankedFinding> ranked = BaselineRanker.Rank(findings, Epss(("CVE-2025-0002", 0.0001)), null);

        Assert.Equal(new[] { "B-tiny-epss", "A-no-epss" }, Order(ranked));
        Assert.Null(ranked[1].Signals.Epss);
    }

    [Fact]
    public void Ties_are_broken_by_id_then_package_then_version_so_the_result_is_stable()
    {
        Finding[] findings =
        [
            Finding("B-1", package: "Z"),
            Finding("A-1", package: "Z"),
            Finding("A-1", package: "A"),
        ];

        IReadOnlyList<RankedFinding> ranked = BaselineRanker.Rank(findings, null, null);

        Assert.Equal(new[] { "A-1|A", "A-1|Z", "B-1|Z" }, ranked.Select(r => $"{r.Id}|{r.Package.Id}").ToArray());
    }

    [Fact]
    public void The_input_order_never_changes_the_output()
    {
        Finding[] findings =
        [
            Finding("A", aliases: ["CVE-2025-0001"], vectors: [Critical]),
            Finding("B", aliases: ["CVE-2025-0002"], vectors: [Medium]),
            Finding("C", aliases: ["CVE-2025-0003"], severity: "HIGH"),
            Finding("D"),
        ];
        EpssData epss = Epss(("CVE-2025-0002", 0.3), ("CVE-2025-0003", 0.3));
        KevData kev = Kev("CVE-2025-0001");

        string[] expected = Order(BaselineRanker.Rank(findings, epss, kev));
        Random random = new(7);

        for (int i = 0; i < 20; i++)
        {
            Finding[] shuffled = findings.OrderBy(_ => random.Next()).ToArray();
            Assert.Equal(expected, Order(BaselineRanker.Rank(shuffled, epss, kev)));
        }
    }

    [Fact]
    public void The_highest_epss_among_the_findings_cves_is_used()
    {
        Finding finding = Finding("A", aliases: ["CVE-2025-0001", "cve-2025-0002"]);

        RankedFinding ranked = Assert.Single(BaselineRanker.Rank([finding], Epss(("CVE-2025-0001", 0.1), ("CVE-2025-0002", 0.7)), null));

        Assert.Equal("CVE-2025-0002", ranked.Signals.Epss!.Cve);
        Assert.Equal(0.7, ranked.Signals.Epss.Probability);
    }

    [Fact]
    public void A_cve_used_as_the_advisory_id_counts_too()
    {
        Finding finding = Finding("CVE-2025-0009");

        RankedFinding ranked = Assert.Single(BaselineRanker.Rank([finding], null, Kev("CVE-2025-0009")));

        Assert.Equal("CVE-2025-0009", ranked.Signals.Kev!.Cve);
    }

    [Fact]
    public void Findings_without_cves_get_no_epss_or_kev_signal()
    {
        Finding finding = Finding("GHSA-only", aliases: ["GHSA-xxxx-yyyy-zzzz"]);

        RankedFinding ranked = Assert.Single(BaselineRanker.Rank([finding], Epss(("CVE-2025-0001", 0.9)), Kev("CVE-2025-0001")));

        Assert.Null(ranked.Signals.Epss);
        Assert.Null(ranked.Signals.Kev);
    }

    [Fact]
    public void The_highest_cvss_v3_score_among_the_published_vectors_is_used_and_other_versions_are_ignored()
    {
        Finding finding = Finding(
            "A",
            vectors: [Medium, Critical, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"]);

        RankedFinding ranked = Assert.Single(BaselineRanker.Rank([finding], null, null));

        Assert.Equal(9.8, ranked.Signals.Cvss!.BaseScore);
        Assert.Equal("CRITICAL", ranked.Signals.Cvss.Rating);
    }

    [Fact]
    public void Only_a_v4_vector_gives_no_cvss_signal()
    {
        Finding finding = Finding("A", vectors: ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"], severity: "HIGH");

        RankedFinding ranked = Assert.Single(BaselineRanker.Rank([finding], null, null));

        Assert.Null(ranked.Signals.Cvss);
        Assert.Equal("HIGH", ranked.Severity);
    }

    [Fact]
    public void Cve_ids_are_normalized_filtered_distinct_and_sorted()
    {
        Finding finding = Finding("GHSA-1", aliases: ["cve-2025-0002", "CVE-2025-0001", "CVE-2025-0001", "CVE-25-1", "GHSA-x", " CVE-2024-12345 "]);

        Assert.Equal(
            new[] { "CVE-2024-12345", "CVE-2025-0001", "CVE-2025-0002" },
            BaselineRanker.CveIds(finding).ToArray());
    }

    [Fact]
    public void An_empty_input_gives_an_empty_ranking()
    {
        Assert.Empty(BaselineRanker.Rank([], null, null));
    }
}

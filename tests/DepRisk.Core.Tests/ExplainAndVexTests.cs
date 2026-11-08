using DepRisk.Core;
using DepRisk.Core.Explain;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;
using DepRisk.Core.Vex;
using Xunit;

namespace DepRisk.Core.Tests;

public class ExplainAndVexTests
{
    private static readonly ToolInfo Tool = new("deprisk", "0.0.0-test");

    private static RankedFinding F(
        int rank,
        string id,
        string package = "Pkg",
        string version = "1.0.0",
        string[]? aliases = null,
        string? severity = null,
        double? cvss = null,
        double? epss = null,
        bool kev = false,
        bool ransomware = false,
        bool direct = true,
        string[]? fixedIn = null,
        string? label = null,
        string reason = "static-path",
        string? symbol = null) =>
        new(
            rank,
            id,
            aliases ?? [],
            $"summary of {id}",
            severity,
            new FindingPackage(package, version),
            fixedIn ?? [],
            [new FindingLocation("App", "net10.0", direct)],
            new FindingSignals(
                cvss is null ? null : new CvssSignal("3.1", "CVSS:3.1/AV:N", cvss.Value, "HIGH"),
                epss is null ? null : new EpssSignal("CVE-2025-1", epss.Value, 0.5),
                kev ? new KevSignal("CVE-2025-1", "2025-01-01", ransomware) : null),
            label is null ? null : new FindingReach(label, reason, symbol));

    private static RankingResult Ranking(params RankedFinding[] findings) =>
        new(
            1,
            Tool,
            "nuget",
            RankingResult.BaselineMethod,
            RankingResult.BaselineOrdering,
            new AdvisorySourceInfo("osv", new string('a', 64), findings.Length, 0, 0, 0),
            new SignalSources(null, null),
            1,
            findings.Length,
            0,
            findings);

    private static ExplainFinding One(RankingResult ranking, string id, ReachabilityResult? reach = null) =>
        Assert.Single(Explainer.Explain(ranking, reach, Tool, id, null).Findings);

    // --- selection ---

    [Fact]
    public void A_finding_is_found_by_its_id_or_an_alias_ignoring_case_and_can_be_narrowed_by_package()
    {
        RankingResult ranking = Ranking(
            F(1, "GHSA-1", "A", aliases: ["CVE-2099-1"]),
            F(2, "GHSA-1", "B", aliases: ["CVE-2099-1"]),
            F(3, "GHSA-2", "A"));

        Assert.Equal(2, Explainer.Explain(ranking, null, Tool, "cve-2099-1", null).Findings.Count);
        Assert.Equal(2, Explainer.Explain(ranking, null, Tool, "ghsa-1", null).Findings.Count);
        Assert.Equal("B", Assert.Single(Explainer.Explain(ranking, null, Tool, "GHSA-1", "b").Findings).Finding.Package.Id);
    }

    [Fact]
    public void A_missing_finding_is_an_input_error_that_lists_what_exists()
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => Explainer.Explain(Ranking(F(1, "GHSA-1"), F(2, "GHSA-2")), null, Tool, "NOPE", null));

        Assert.Contains("no finding for 'NOPE'", error.Message);
        Assert.Contains("GHSA-1, GHSA-2", error.Message);
        Assert.Contains("There are no findings", Assert.Throws<InvalidInputException>(() => Explainer.Explain(Ranking(), null, Tool, "X", null)).Message);
        Assert.Contains("in package 'Q'", Assert.Throws<InvalidInputException>(() => Explainer.Explain(Ranking(F(1, "GHSA-1")), null, Tool, "GHSA-1", "Q")).Message);
    }

    // --- position (baseline) ---

    [Fact]
    public void The_baseline_explanation_names_the_first_key_that_decided_the_order()
    {
        RankingResult ranking = Ranking(
            F(1, "A-KEV", kev: true),
            F(2, "B-EPSS", epss: 0.50),
            F(3, "C-EPSS-LOW", epss: 0.10, cvss: 9.0),
            F(4, "D-CVSS", cvss: 9.0),
            F(5, "E-CVSS-LOW", cvss: 5.0),
            F(6, "F-SEV", severity: "HIGH"),
            F(7, "G-SEV-LOW", severity: "LOW"),
            F(8, "H-ID"),
            F(9, "I-ID"));

        string Why(string id) => string.Join(" ", One(ranking, id).Position.Why);

        // Each finding is compared with the one ranked directly above it (the first one with the one below it).
        Assert.Contains("Ranked first of 9, ahead of #2 (B-EPSS) because it is in the CISA KEV catalog and the other is not.", Why("A-KEV"));
        Assert.Contains("#1 (A-KEV) ranks higher because it is in the CISA KEV catalog and the other is not.", Why("B-EPSS"));
        Assert.Contains("#2 (B-EPSS) ranks higher because its EPSS probability is higher (0.5000 against 0.1000; KEV status is equal).", Why("C-EPSS-LOW"));
        Assert.Contains("#3 (C-EPSS-LOW) ranks higher because its EPSS probability is higher (0.1000 against none; KEV status is equal).", Why("D-CVSS"));
        Assert.Contains("#4 (D-CVSS) ranks higher because its CVSS base score is higher (9.0 against 5.0; KEV and EPSS are equal).", Why("E-CVSS-LOW"));
        Assert.Contains("#5 (E-CVSS-LOW) ranks higher because its CVSS base score is higher (5.0 against none; KEV and EPSS are equal).", Why("F-SEV"));
        Assert.Contains("#6 (F-SEV) ranks higher because the database rates it more severe (HIGH against LOW; KEV, EPSS, and CVSS are equal).", Why("G-SEV-LOW"));
        Assert.Contains("#7 (G-SEV-LOW) ranks higher because the database rates it more severe (LOW against unrated;", Why("H-ID"));
        Assert.Contains("#8 (H-ID) ranks higher only by identifier: every signal is equal.", Why("I-ID"));
        Assert.Contains("Reachability does not change it", Why("A-KEV"));
    }

    [Fact]
    public void A_single_finding_says_so()
    {
        Assert.Contains("It is the only finding.", One(Ranking(F(1, "ONLY")), "ONLY").Position.Why);
    }

    [Fact]
    public void The_position_carries_the_rank_the_method_and_the_total()
    {
        ExplainPosition position = One(Ranking(F(1, "A"), F(2, "B")), "B").Position;

        Assert.Equal((2, 2, null), (position.Rank, position.Of, position.BaselineRank));
        Assert.Equal(RankingResult.BaselineMethod, position.Method);
    }

    // --- evidence ---

    [Fact]
    public void The_evidence_is_built_from_the_data()
    {
        RankingResult ranking = Ranking(F(1, "GHSA-1", "Newtonsoft.Json", "12.0.1", kev: true, ransomware: true, epss: 0.4, cvss: 9.8, fixedIn: ["13.0.1"], direct: true));

        string evidence = string.Join("\n", One(ranking, "GHSA-1").Evidence);

        Assert.Contains("Newtonsoft.Json 12.0.1 is in an affected version range of GHSA-1; fixed in 13.0.1.", evidence);
        Assert.Contains("installed as a direct dependency of App (target net10.0)", evidence);
        Assert.Contains("It is in the CISA KEV catalog (CVE-2025-1, added 2025-01-01, known ransomware use).", evidence);
        Assert.Contains("EPSS: probability 0.4000, percentile 0.5000", evidence);
        Assert.Contains("CVSS 3.1 base score 9.8 (HIGH).", evidence);
        Assert.Contains("Reachability was not analyzed", evidence);
    }

    [Fact]
    public void Missing_signals_are_described_as_missing_never_as_zero()
    {
        string evidence = string.Join("\n", One(Ranking(F(1, "GHSA-1", direct: false, severity: "MODERATE")), "GHSA-1").Evidence);

        Assert.Contains("no fixed version is known", evidence);
        Assert.Contains("transitive dependency", evidence);
        Assert.Contains("not in the CISA KEV catalog (or no KEV data was given)", evidence);
        Assert.Contains("No EPSS value is available", evidence);
        Assert.Contains("No CVSS v3 score is available; the database rating is MODERATE.", evidence);
    }

    [Fact]
    public void The_reachability_path_is_listed_step_by_step_with_its_provenance()
    {
        RankedFinding finding = F(1, "GHSA-1", label: "reachable", symbol: "A.B.C");
        ReachVerdict verdict = new(
            "reachable",
            "static-path",
            "A.B.C",
            [new ReachPathEdge("App.Main", "App.Load", "static", "Program.cs", 9), new ReachPathEdge("App.Load", "A.B.C", "dynamic", "Program.cs", 14)],
            ["analyst note 1"]);
        ReachabilityResult reach = ReachResult([new ReachFinding(new Finding("GHSA-1", [], null, null, [], new FindingPackage("Pkg", "1.0.0"), [], finding.Locations), verdict)]);

        ExplainFinding explained = One(Ranking(finding), "GHSA-1", reach);
        string evidence = string.Join("\n", explained.Evidence);

        Assert.Same(verdict, explained.Reachability);
        Assert.Contains("Reachability: reachable: a call path exists.", evidence);
        Assert.Contains("The symbol reached is A.B.C.", evidence);
        Assert.Contains("Path step 1: App.Main -> App.Load, static (Program.cs:9).", evidence);
        Assert.Contains("Path step 2: App.Load -> A.B.C, dynamic (Program.cs:14).", evidence);
        Assert.Contains("The symbols come from: analyst note 1.", evidence);
    }

    [Theory]
    [InlineData(null, "Add --symbols")]
    [InlineData("no-symbols", "A symbol map entry for this advisory")]
    [InlineData("transitive-package-code-not-analyzed", "only reached through other packages")]
    [InlineData("symbol-list-incomplete", "marking the entry complete: true would turn 'unknown' into 'unreachable'")]
    [InlineData("incomplete-analysis", "could not be read completely")]
    [InlineData("unresolved-reflection", "uses reflection")]
    [InlineData("unresolved-receiver", "unknown type")]
    [InlineData("no-entrypoints", "--entrypoints public-api")]
    [InlineData("no-analyzer-for-ecosystem", "only C# has one so far")]
    [InlineData("no-path", "The verdict stands unless")]
    public void What_would_change_it_depends_on_why_the_verdict_is_what_it_is(string? reason, string expected)
    {
        RankedFinding finding = reason is null ? F(1, "GHSA-1", fixedIn: ["2.0.0"]) : F(1, "GHSA-1", fixedIn: ["2.0.0"], label: "unknown", reason: reason);

        string lines = string.Join("\n", One(Ranking(finding), "GHSA-1").WhatWouldChange);

        Assert.Contains(expected, lines);
        Assert.Contains("Upgrading Pkg to 2.0.0 or later removes this finding.", lines);
    }

    [Fact]
    public void Control_characters_from_advisory_data_never_reach_the_explanation()
    {
        RankedFinding finding = F(1, "GHSA-1\u001b[31m", "Pkg\u001b[2J");
        ExplainFinding explained = One(Ranking(finding), "GHSA-1\u001b[31m");

        Assert.DoesNotContain('\u001b', string.Join("\n", explained.Evidence.Concat(explained.Position.Why).Concat(explained.WhatWouldChange)));
    }

    // --- VEX decisions ---

    private static ReachabilityResult ReachResult(IReadOnlyList<ReachFinding> findings, int filesWithErrors = 0, int filesSkipped = 0, bool analyzer = true) =>
        new(
            1,
            Tool,
            "nuget",
            new AdvisorySourceInfo("osv", new string('a', 64), 1, 0, 0, 0),
            new SymbolMapInfo("maps", new string('b', 64), 1, 1),
            analyzer ? new ReachAnalyzerInfo("deprisk-reach", "1.2.3", new string('c', 64)) : null,
            analyzer ? new ReachSourceInfo(new string('d', 64), 10, filesSkipped, filesWithErrors, 5, 5, 1) : null,
            new ReachSummary(0, 0, 0, 0),
            findings,
            []);

    private static ReachabilityResult ReachFor(RankedFinding finding, string label, string reason, string[]? sources = null, int filesWithErrors = 0, int filesSkipped = 0) =>
        ReachResult(
            [new ReachFinding(new Finding(finding.Id, [], null, null, [], finding.Package, finding.FixedVersions, finding.Locations), new ReachVerdict(label, reason, null, [], sources ?? ["curated"]))],
            filesWithErrors,
            filesSkipped);

    [Fact]
    public void Unreachable_with_every_condition_met_is_not_affected_with_a_justification_and_the_evidence()
    {
        RankedFinding finding = F(1, "GHSA-1", label: "unreachable", reason: "no-path");

        VexStatement statement = VexDecision.For(finding, ReachFor(finding, "unreachable", "no-path"));

        Assert.Equal("not_affected", statement.Status);
        Assert.Equal("vulnerable_code_not_in_execute_path", statement.Justification);
        Assert.Contains("deprisk-reach 1.2.3", statement.ImpactStatement);
        Assert.Contains("source digest dddddddddddd", statement.ImpactStatement);
        Assert.Contains("symbol maps digest bbbbbbbbbbbb", statement.ImpactStatement);
        Assert.Contains("not a proof", statement.ImpactStatement);
        Assert.Null(statement.ActionStatement);
    }

    [Fact]
    public void Not_affected_is_re_checked_and_degrades_when_a_condition_does_not_hold()
    {
        RankedFinding transitive = F(1, "GHSA-1", direct: false, label: "unreachable", reason: "no-path");
        RankedFinding mixed = F(1, "GHSA-1", label: "unreachable", reason: "no-path") with { Locations = [new FindingLocation("A", "t", true), new FindingLocation("B", "t", false)] };
        RankedFinding direct = F(1, "GHSA-1", label: "unreachable", reason: "no-path");

        Assert.Equal("under_investigation", VexDecision.For(transitive, ReachFor(transitive, "unreachable", "no-path")).Status);
        Assert.Equal("under_investigation", VexDecision.For(mixed, ReachFor(mixed, "unreachable", "no-path")).Status);
        Assert.Equal("under_investigation", VexDecision.For(direct, ReachFor(direct, "unreachable", "no-path", filesWithErrors: 1)).Status);
        Assert.Equal("under_investigation", VexDecision.For(direct, ReachFor(direct, "unreachable", "no-path", filesSkipped: 1)).Status);
        Assert.Equal("under_investigation", VexDecision.For(direct, ReachFor(direct, "unreachable", "no-path", sources: [])).Status);
        Assert.Equal("under_investigation", VexDecision.For(direct, ReachResult([], analyzer: false)).Status);

        VexStatement degraded = VexDecision.For(transitive, ReachFor(transitive, "unreachable", "no-path"));
        Assert.Null(degraded.Justification);
        Assert.Contains("conditions for stating that the product is not affected were not all met", degraded.StatusNotes);
    }

    [Fact]
    public void Reachable_is_affected_with_an_action_that_names_the_fix_or_says_there_is_none()
    {
        RankedFinding fixable = F(1, "GHSA-1", fixedIn: ["2.0.0"], label: "reachable", symbol: "A.B.C");
        RankedFinding unfixable = F(1, "GHSA-1", label: "reachable", symbol: "A.B.C");

        VexStatement a = VexDecision.For(fixable, ReachFor(fixable, "reachable", "static-path"));
        VexStatement b = VexDecision.For(unfixable, ReachFor(unfixable, "reachable", "static-path"));

        Assert.Equal("affected", a.Status);
        Assert.Equal("Upgrade Pkg to 2.0.0 or later.", a.ActionStatement);
        Assert.Contains("A.B.C", a.ImpactStatement);
        Assert.Contains("No fixed version is known for Pkg", b.ActionStatement);
        Assert.Null(a.Justification);
    }

    [Theory]
    [InlineData("possibly-reachable", "dynamic-path", "only through dynamic edges")]
    [InlineData("unknown", "no-symbols", "Reachability is unknown: no symbol list")]
    [InlineData("unknown", "symbol-list-incomplete", "not declared complete")]
    public void Everything_else_is_under_investigation_with_a_note(string label, string reason, string expected)
    {
        RankedFinding finding = F(1, "GHSA-1", label: label, reason: reason);

        VexStatement statement = VexDecision.For(finding, ReachFor(finding, label, reason));

        Assert.Equal("under_investigation", statement.Status);
        Assert.Contains(expected, statement.StatusNotes);
        Assert.Null(statement.Justification);
        Assert.Null(statement.ImpactStatement);
    }

    [Fact]
    public void Without_a_reachability_analysis_every_finding_is_under_investigation()
    {
        VexStatement statement = VexDecision.For(F(1, "GHSA-1"), null);

        Assert.Equal("under_investigation", statement.Status);
        Assert.Contains("not analyzed", statement.StatusNotes);
    }
}

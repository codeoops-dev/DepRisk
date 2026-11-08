using System.Globalization;
using DepRisk.Core.Model;
using DepRisk.Core.Ranking;
using DepRisk.Core.Reach;

namespace DepRisk.Core.Explain;

/// <summary>
/// Explains findings of a ranking: where they stand, the evidence, and what would change the picture. Every sentence is built from
/// the data in the result by a fixed template, so an explanation can be checked line by line and is identical on every run.
/// </summary>
public static class Explainer
{
    public static ExplainResult Explain(RankingResult ranking, ReachabilityResult? reach, ToolInfo tool, string query, string? package)
    {
        ArgumentNullException.ThrowIfNull(ranking);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentException.ThrowIfNullOrWhiteSpace(query);

        List<RankedFinding> matches = ranking.Findings
            .Where(f => (f.Id.Equals(query, StringComparison.OrdinalIgnoreCase) || f.Aliases.Any(a => a.Equals(query, StringComparison.OrdinalIgnoreCase)))
                && (package is null || f.Package.Id.Equals(package, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (matches.Count == 0)
        {
            string known = string.Join(", ", ranking.Findings.Select(f => SafeText.Clean(f.Id, 40)).Distinct(StringComparer.Ordinal).Take(10));
            throw new InvalidInputException(
                $"no finding for '{SafeText.Clean(query, 80)}'{(package is null ? string.Empty : $" in package '{SafeText.Clean(package, 80)}'")}. "
                + (ranking.Findings.Count == 0 ? "There are no findings." : $"Findings: {known}{(ranking.Findings.Count > 10 ? ", ..." : string.Empty)}."));
        }

        List<ExplainFinding> explained = matches.Select(f => ExplainOne(f, ranking, reach)).ToList();

        return new ExplainResult(ExplainResult.CurrentSchemaVersion, tool, ranking.Ecosystem, ranking.Method, query, explained);
    }

    private static ExplainFinding ExplainOne(RankedFinding finding, RankingResult ranking, ReachabilityResult? reach)
    {
        ReachVerdict? verdict = reach?.Findings
            .FirstOrDefault(r => r.Finding.Id.Equals(finding.Id, StringComparison.OrdinalIgnoreCase)
                && r.Finding.Package.Id.Equals(finding.Package.Id, StringComparison.OrdinalIgnoreCase)
                && r.Finding.Package.Version == finding.Package.Version)?.Reachability;

        return new ExplainFinding(finding, verdict, Position(finding, ranking), Evidence(finding, verdict), WhatWouldChange(finding, verdict, ranking));
    }

    // --- position ---

    private static ExplainPosition Position(RankedFinding finding, RankingResult ranking)
    {
        int total = ranking.Findings.Count;
        List<string> why = [];
        RankedFinding? above = ranking.Findings.FirstOrDefault(f => f.Rank == finding.Rank - 1);
        RankedFinding? below = ranking.Findings.FirstOrDefault(f => f.Rank == finding.Rank + 1);

        if (ranking.Model is { } model && finding.Risk is { } risk)
        {
            double mine = RiskRanker(risk, model.RankBy);
            why.Add($"Ranked #{finding.Rank} of {total} by the {model.RankBy} of its modeled risk, {Num(mine)} (reach {Num(risk.ReachMean)} x exploit {Num(risk.ExploitMean)} x impact {Num(risk.ImpactMean)} on average).");

            if (above?.Risk is { } aboveRisk)
            {
                why.Add($"#{above.Rank} ({SafeText.Clean(above.Id, 60)}) has {Num(RiskRanker(aboveRisk, model.RankBy))}.");
            }

            if (finding.BaselineRank is { } baseline)
            {
                why.Add(baseline == finding.Rank
                    ? $"The baseline method (KEV, then EPSS, then CVSS) gives it the same position, #{baseline}."
                    : $"The baseline method (KEV, then EPSS, then CVSS) would rank it #{baseline}: " + (baseline > finding.Rank ? "reachability and the uncertainty in the signals move it up." : "reachability and the uncertainty in the signals move it down."));
            }

            why.Add($"The parameters are {model.Calibration}: the numbers order findings by modeled risk and are not probabilities of real-world loss.");
            return new ExplainPosition(ranking.Method, finding.Rank, total, finding.BaselineRank, why);
        }

        if (total == 1)
        {
            why.Add("It is the only finding.");
        }
        else if (above is not null)
        {
            why.Add($"Ranked #{finding.Rank} of {total}. #{above.Rank} ({SafeText.Clean(above.Id, 60)}) ranks higher {DecidedBy(above, finding)}");
        }
        else if (below is not null)
        {
            why.Add($"Ranked first of {total}, ahead of #{below.Rank} ({SafeText.Clean(below.Id, 60)}) {DecidedBy(finding, below)}");
        }

        why.Add("Order of the baseline method: in CISA KEV first, then EPSS probability, then CVSS base score, then database severity, then id. Reachability does not change it.");

        return new ExplainPosition(ranking.Method, finding.Rank, total, null, why);
    }

    private static double RiskRanker(FindingRisk risk, string statistic) => DepRisk.Core.Risk.RiskRanker.Statistic(risk, statistic);

    /// <summary>The first key of the baseline ordering on which the two findings differ, in words.</summary>
    private static string DecidedBy(RankedFinding higher, RankedFinding lower)
    {
        bool kevHigh = higher.Signals.Kev is not null;
        bool kevLow = lower.Signals.Kev is not null;

        if (kevHigh != kevLow)
        {
            return kevHigh ? "because it is in the CISA KEV catalog and the other is not." : "(unexpected order).";
        }

        double epssHigh = higher.Signals.Epss?.Probability ?? -1;
        double epssLow = lower.Signals.Epss?.Probability ?? -1;

        if (epssHigh != epssLow)
        {
            return $"because its EPSS probability is higher ({EpssText(higher)} against {EpssText(lower)}; KEV status is equal).";
        }

        double cvssHigh = higher.Signals.Cvss?.BaseScore ?? -1;
        double cvssLow = lower.Signals.Cvss?.BaseScore ?? -1;

        if (cvssHigh != cvssLow)
        {
            return $"because its CVSS base score is higher ({CvssText(higher)} against {CvssText(lower)}; KEV and EPSS are equal).";
        }

        if (BaselineRanker.SeverityRank(higher.Severity) != BaselineRanker.SeverityRank(lower.Severity))
        {
            return $"because the database rates it more severe ({higher.Severity ?? "unrated"} against {lower.Severity ?? "unrated"}; KEV, EPSS, and CVSS are equal).";
        }

        return "only by identifier: every signal is equal.";
    }

    // --- evidence ---

    private static IReadOnlyList<string> Evidence(RankedFinding f, ReachVerdict? verdict)
    {
        List<string> lines = [];
        string pkg = $"{SafeText.Clean(f.Package.Id, 80)} {SafeText.Clean(f.Package.Version, 40)}";

        lines.Add(f.FixedVersions.Count == 0
            ? $"{pkg} is in an affected version range of {SafeText.Clean(f.Id, 60)}; no fixed version is known."
            : $"{pkg} is in an affected version range of {SafeText.Clean(f.Id, 60)}; fixed in {string.Join(", ", f.FixedVersions.Select(v => SafeText.Clean(v, 40)))}.");

        foreach (FindingLocation location in f.Locations.Take(5))
        {
            lines.Add($"It is installed as a {(location.IsDirect ? "direct" : "transitive")} dependency of {SafeText.Clean(location.Project, 80)} (target {SafeText.Clean(location.Target, 60)}).");
        }

        if (f.Locations.Count > 5)
        {
            lines.Add($"... and {f.Locations.Count - 5} more location(s).");
        }

        lines.Add(f.Signals.Kev is { } kev
            ? $"It is in the CISA KEV catalog ({SafeText.Clean(kev.Cve, 30)}{(kev.DateAdded is null ? string.Empty : ", added " + SafeText.Clean(kev.DateAdded, 20))}{(kev.KnownRansomwareUse ? ", known ransomware use" : string.Empty)})."
            : "It is not in the CISA KEV catalog (or no KEV data was given).");
        lines.Add(f.Signals.Epss is { } epss
            ? $"EPSS: probability {epss.Probability.ToString("0.0000", CultureInfo.InvariantCulture)}, percentile {epss.Percentile.ToString("0.0000", CultureInfo.InvariantCulture)} ({SafeText.Clean(epss.Cve, 30)})."
            : "No EPSS value is available for it (or no EPSS data was given).");
        lines.Add(f.Signals.Cvss is { } cvss
            ? $"CVSS {SafeText.Clean(cvss.Version, 10)} base score {cvss.BaseScore.ToString("0.0", CultureInfo.InvariantCulture)} ({SafeText.Clean(cvss.Rating, 20)})."
            : $"No CVSS v3 score is available; the database rating is {(f.Severity is null ? "absent" : SafeText.Clean(f.Severity, 20))}.");

        if (f.Reachability is { } reach)
        {
            lines.Add($"Reachability: {reach.Label}: {ReachLabels.Describe(reach.Reason)}.");

            if (verdict is not null)
            {
                if (verdict.Symbol is not null)
                {
                    lines.Add($"The symbol reached is {SafeText.Clean(verdict.Symbol, 120)}.");
                }

                for (int i = 0; i < verdict.Path.Count; i++)
                {
                    ReachPathEdge edge = verdict.Path[i];
                    string where = edge.File is null ? string.Empty : $" ({SafeText.Clean(edge.File, 80)}{(edge.Line is null ? string.Empty : ":" + edge.Line)})";
                    lines.Add($"Path step {i + 1}: {SafeText.Clean(edge.From, 80)} -> {SafeText.Clean(edge.To, 80)}, {edge.Kind}{where}.");
                }

                foreach (string source in verdict.SymbolSources)
                {
                    lines.Add($"The symbols come from: {SafeText.Clean(source, 160)}.");
                }
            }
        }
        else
        {
            lines.Add("Reachability was not analyzed (no symbol maps were given).");
        }

        return lines;
    }

    // --- what would change it ---

    private static IReadOnlyList<string> WhatWouldChange(RankedFinding f, ReachVerdict? verdict, RankingResult ranking)
    {
        List<string> lines = [];

        if (f.FixedVersions.Count > 0)
        {
            lines.Add($"Upgrading {SafeText.Clean(f.Package.Id, 80)} to {SafeText.Clean(f.FixedVersions[0], 40)} or later removes this finding.");
        }
        else
        {
            lines.Add("No fixed version is known: the finding stays until the package is replaced or the advisory data changes.");
        }

        string? reason = f.Reachability?.Reason;

        switch (reason)
        {
            case null:
                lines.Add("Add --symbols (a symbol map for this advisory, docs/symbol-maps.md) to get a reachability verdict.");
                break;
            case ReachLabels.NoSymbols:
                lines.Add("A symbol map entry for this advisory and package (docs/symbol-maps.md) would let the analyzer answer.");
                break;
            case ReachLabels.TransitivePackage:
                lines.Add("This package is only reached through other packages, whose code is not analyzed: a path from your own code would show as reachable; the absence of one cannot be shown.");
                break;
            case ReachLabels.SymbolListIncomplete:
                lines.Add("If the symbol list really contains every public way to reach the flaw, marking the entry complete: true would turn 'unknown' into 'unreachable'. That is a claim to make only after checking.");
                break;
            case ReachLabels.IncompleteAnalysis:
                lines.Add("Source files could not be read completely (see the notes of 'deprisk reach'); fixing or excluding them lets the analysis finish.");
                break;
            case ReachLabels.UnresolvedReflection or ReachLabels.UnresolvedReceiver:
                lines.Add("Code in the reachable part of the application uses reflection or calls on values of unknown type; naming the types involved, or restricting what is reachable, would let the analysis decide.");
                break;
            case ReachLabels.NoEntrypoints:
                lines.Add("No entrypoint was found: for a library use --entrypoints public-api, otherwise name entrypoints with --entrypoint.");
                break;
            case ReachLabels.NoAnalyzerForEcosystem:
                lines.Add("Reachability needs an analyzer for this ecosystem; only C# has one so far.");
                break;
            case ReachLabels.NoPath:
                lines.Add("The verdict stands unless the code changes so that a path appears, or the symbol list turns out to be incomplete.");
                break;
        }

        if (ranking.Model is null)
        {
            lines.Add("--model risk shows the distribution of modeled risk for this finding instead of only its place in the baseline order.");
        }

        return lines;
    }

    private static string Num(double value) => value.ToString("0.00", CultureInfo.InvariantCulture);

    private static string EpssText(RankedFinding f) => f.Signals.Epss is { } e ? e.Probability.ToString("0.0000", CultureInfo.InvariantCulture) : "none";

    private static string CvssText(RankedFinding f) => f.Signals.Cvss is { } c ? c.BaseScore.ToString("0.0", CultureInfo.InvariantCulture) : "none";
}

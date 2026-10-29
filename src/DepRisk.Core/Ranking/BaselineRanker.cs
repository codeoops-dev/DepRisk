using System.Text.RegularExpressions;
using DepRisk.Core.Cvss;
using DepRisk.Core.Model;
using DepRisk.Core.Signals;

namespace DepRisk.Core.Ranking;

/// <summary>
/// The baseline ("B2") ordering: findings listed in the CISA KEV catalog first, then by EPSS probability, then by CVSS
/// base score, then by the database's own severity rating, then by id for a stable result. Each key only orders findings
/// that are equal on the keys before it, so no weights or thresholds have to be invented. Missing data sorts last on its key.
/// This is deliberately simple: it is the reference that the uncertainty-aware model is measured against.
/// </summary>
public static partial class BaselineRanker
{
    public static IReadOnlyList<RankedFinding> Rank(IReadOnlyList<Finding> findings, EpssData? epss, KevData? kev)
    {
        ArgumentNullException.ThrowIfNull(findings);

        List<(Finding Finding, FindingSignals Signals)> enriched = findings
            .Select(f => (Finding: f, Signals: SignalsFor(f, epss, kev)))
            .ToList();

        return enriched
            .OrderByDescending(e => e.Signals.Kev is not null)
            .ThenByDescending(e => e.Signals.Epss?.Probability ?? -1)
            .ThenByDescending(e => e.Signals.Cvss?.BaseScore ?? -1)
            .ThenByDescending(e => SeverityRank(e.Finding.Severity))
            .ThenBy(e => e.Finding.Id, StringComparer.Ordinal)
            .ThenBy(e => e.Finding.Package.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Finding.Package.Version, StringComparer.Ordinal)
            .Select((e, index) => new RankedFinding(
                index + 1,
                e.Finding.Id,
                e.Finding.Aliases,
                e.Finding.Summary,
                e.Finding.Severity,
                e.Finding.Package,
                e.Finding.FixedVersions,
                e.Finding.Locations,
                e.Signals))
            .ToList();
    }

    /// <summary>The CVE identifiers of a finding: its id and aliases that have the CVE form, upper-cased, sorted, distinct.</summary>
    public static IReadOnlyList<string> CveIds(Finding finding) =>
        finding.Aliases
            .Append(finding.Id)
            .Select(a => a.Trim().ToUpperInvariant())
            .Where(a => CvePattern().IsMatch(a))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

    public static int SeverityRank(string? severity) => severity?.ToUpperInvariant() switch
    {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MODERATE" or "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    };

    private static FindingSignals SignalsFor(Finding finding, EpssData? epss, KevData? kev)
    {
        IReadOnlyList<string> cves = CveIds(finding);

        // CVSS: the highest base score among the v3.x vectors published with the advisory (conservative).
        CvssSignal? cvss = finding.Scores
            .Select(s => CvssV3.TryScore(s.Score, out CvssScore? parsed) ? parsed : null)
            .Where(s => s is not null)
            .OrderByDescending(s => s!.BaseScore)
            .ThenByDescending(s => s!.Version, StringComparer.Ordinal)
            .Select(s => new CvssSignal(s!.Version, s.Vector, s.BaseScore, s.Rating))
            .FirstOrDefault();

        // EPSS: the highest probability among the finding's CVEs.
        EpssSignal? epssSignal = null;

        if (epss is not null)
        {
            foreach (string cve in cves)
            {
                if (epss.Scores.TryGetValue(cve, out EpssScore? score)
                    && (epssSignal is null || score.Probability > epssSignal.Probability))
                {
                    epssSignal = new EpssSignal(cve, score.Probability, score.Percentile);
                }
            }
        }

        // KEV: listed if any of the finding's CVEs is in the catalog.
        KevSignal? kevSignal = null;

        if (kev is not null)
        {
            foreach (string cve in cves)
            {
                if (kev.Entries.TryGetValue(cve, out KevEntry? entry))
                {
                    kevSignal = new KevSignal(entry.CveId, entry.DateAdded, entry.KnownRansomwareUse);
                    break;
                }
            }
        }

        return new FindingSignals(cvss, epssSignal, kevSignal);
    }

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$", RegexOptions.CultureInvariant)]
    private static partial Regex CvePattern();
}

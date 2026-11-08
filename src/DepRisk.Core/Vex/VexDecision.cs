using DepRisk.Core.Model;
using DepRisk.Core.Reach;

namespace DepRisk.Core.Vex;

/// <summary>What a VEX statement says about one finding (OpenVEX 0.2.0 vocabulary).</summary>
public sealed record VexStatement(string Status, string? Justification, string? ImpactStatement, string? ActionStatement, string? StatusNotes);

/// <summary>
/// Turns reachability verdicts into VEX statuses, conservatively. A VEX statement is made for other people to rely on, so
/// <c>not_affected</c> is the hardest to earn: only a verdict of "unreachable" (which the analyzer gives only for a declared-complete
/// symbol list, fully read source, no unreadable reflection or receiver, and a direct package), re-checked here against the analysis
/// that produced it. "Reachable" is "affected" with an action. Everything else, including "possibly reachable", "unknown", and "not
/// analyzed", is "under_investigation": the honest status when the question is open.
/// </summary>
public static class VexDecision
{
    public const string NotAffected = "not_affected";
    public const string Affected = "affected";
    public const string UnderInvestigation = "under_investigation";
    public const string NotInExecutePath = "vulnerable_code_not_in_execute_path";

    public static VexStatement For(RankedFinding finding, ReachabilityResult? reach)
    {
        ArgumentNullException.ThrowIfNull(finding);

        FindingReach? verdict = finding.Reachability;

        if (verdict is null || reach is null)
        {
            return new VexStatement(UnderInvestigation, null, null, null, "Reachability of the vulnerable code was not analyzed; the finding is by package version only.");
        }

        switch (verdict.Label)
        {
            case ReachLabels.Unreachable:
                return Unreachable(finding, reach);

            case ReachLabels.Reachable:
                return new VexStatement(
                    Affected,
                    null,
                    $"A call path exists from the application's entrypoints to {verdict.Symbol ?? "a vulnerable symbol"} (deprisk reach).",
                    Action(finding, verdict.Symbol),
                    null);

            case ReachLabels.PossiblyReachable:
                return new VexStatement(UnderInvestigation, null, null, null, "A call path to the vulnerable code exists only through dynamic edges (dispatch, reflection by name, or calls on values of unknown type).");

            default:
                return new VexStatement(UnderInvestigation, null, null, null, $"Reachability is unknown: {ReachLabels.Describe(verdict.Reason)}.");
        }
    }

    private static VexStatement Unreachable(RankedFinding finding, ReachabilityResult reach)
    {
        // Re-check the conditions the verdict rests on. They are enforced upstream; a VEX document is read by others, so they are
        // asked again here and the statement degrades to "under investigation" if any is not met.
        bool direct = finding.Locations.Count > 0 && finding.Locations.All(l => l.IsDirect);
        bool read = reach.Analyzer is not null && reach.Source is { FilesWithErrors: 0, FilesSkipped: 0 };
        bool sourced = reach.Findings.FirstOrDefault(r => r.Finding.Id == finding.Id && r.Finding.Package.Id == finding.Package.Id)?.Reachability.SymbolSources.Count > 0;

        if (!direct || !read || !sourced)
        {
            return new VexStatement(
                UnderInvestigation,
                null,
                null,
                null,
                "The analysis found no path, but the conditions for stating that the product is not affected were not all met (direct dependency, every source file read, a symbol list with provenance).");
        }

        string evidence =
            $"deprisk reach found no call path from the application's entrypoints to the vulnerable symbols of {finding.Package.Id}. "
            + "The symbol list is declared complete, every source file was read, and the package is a direct dependency. "
            + $"Analyzer {reach.Analyzer!.Name} {reach.Analyzer.Version}; source digest {reach.Source!.SourceDigest[..12]}; symbol maps digest {reach.SymbolMaps.Digest[..12]}. "
            + "This is a statement about a conservative call graph built from source, not a proof.";

        return new VexStatement(NotAffected, NotInExecutePath, evidence, null, null);
    }

    private static string Action(RankedFinding finding, string? symbol) =>
        finding.FixedVersions.Count > 0
            ? $"Upgrade {finding.Package.Id} to {finding.FixedVersions[0]} or later."
            : $"No fixed version is known for {finding.Package.Id}. Avoid or restrict the use of {symbol ?? "the vulnerable symbols"}, or replace the package.";
}

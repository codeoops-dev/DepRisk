namespace DepRisk.Core.Model;

public sealed record CvssSignal(string Version, string Vector, double BaseScore, string Rating);

public sealed record EpssSignal(string Cve, double Probability, double Percentile);

public sealed record KevSignal(string Cve, string? DateAdded, bool KnownRansomwareUse);

/// <summary>The exploitation and severity signals available for one finding. Null means "not available", never "zero".</summary>
public sealed record FindingSignals(CvssSignal? Cvss, EpssSignal? Epss, KevSignal? Kev);

/// <summary>A finding with its position in the baseline ranking (1 = most urgent).</summary>
public sealed record RankedFinding(
    int Rank,
    string Id,
    IReadOnlyList<string> Aliases,
    string? Summary,
    string? Severity,
    FindingPackage Package,
    IReadOnlyList<string> FixedVersions,
    IReadOnlyList<FindingLocation> Locations,
    FindingSignals Signals);

/// <summary>Provenance of an EPSS or KEV data set. Dates are those published inside the data, never the current time.</summary>
public sealed record SignalSourceInfo(string Source, string Digest, string? Version, string? Date, int Entries, int Skipped);

public sealed record SignalSources(SignalSourceInfo? Epss, SignalSourceInfo? Kev);

/// <summary>
/// Result of <c>deprisk rank</c>. Public contract: schemas/ranking.v1.schema.json.
/// Deterministic: no timestamps, no absolute paths.
/// </summary>
public sealed record RankingResult(
    int SchemaVersion,
    ToolInfo Tool,
    string Ecosystem,
    string Method,
    IReadOnlyList<string> Ordering,
    AdvisorySourceInfo Advisories,
    SignalSources Signals,
    int ProjectsScanned,
    int PackagesScanned,
    int PackagesSkipped,
    IReadOnlyList<RankedFinding> Findings)
{
    public const int CurrentSchemaVersion = 1;

    /// <summary>Name of the method, used as baseline "B2" in the evaluation plan.</summary>
    public const string BaselineMethod = "baseline-kev-epss-cvss";

    public static readonly string[] BaselineOrdering = ["kev", "epss", "cvss", "severity", "id"];
}

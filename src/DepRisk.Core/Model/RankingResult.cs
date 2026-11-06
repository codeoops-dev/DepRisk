namespace DepRisk.Core.Model;

public sealed record CvssSignal(string Version, string Vector, double BaseScore, string Rating);

public sealed record EpssSignal(string Cve, double Probability, double Percentile);

public sealed record KevSignal(string Cve, string? DateAdded, bool KnownRansomwareUse);

/// <summary>The exploitation and severity signals available for one finding. Null means "not available", never "zero".</summary>
public sealed record FindingSignals(CvssSignal? Cvss, EpssSignal? Epss, KevSignal? Kev);

/// <summary>
/// The reachability verdict of a finding, as shown in the ranking (<c>deprisk reach</c> has the path). Present only when symbol maps
/// were supplied (<c>--symbols</c>); null means "not analyzed", never "unreachable".
/// </summary>
public sealed record FindingReach(string Label, string Reason, string? Symbol);

/// <summary>The risk distribution of a finding under the uncertainty model (docs/method.md, section 4): R = Reach x Exploit x Impact over Monte Carlo scenarios.</summary>
public sealed record FindingRisk(
    double Mean,
    double P50,
    double P90,
    double P95,
    double Cvar95,
    double ReachMean,
    double ExploitMean,
    double ImpactMean);

/// <summary>
/// A finding with its position (1 = most urgent). In the baseline method reachability does not change the position; with the risk
/// model the position follows <c>Risk</c> and <c>BaselineRank</c> keeps the position the baseline would have given.
/// </summary>
public sealed record RankedFinding(
    int Rank,
    string Id,
    IReadOnlyList<string> Aliases,
    string? Summary,
    string? Severity,
    FindingPackage Package,
    IReadOnlyList<string> FixedVersions,
    IReadOnlyList<FindingLocation> Locations,
    FindingSignals Signals,
    FindingReach? Reachability = null,
    FindingRisk? Risk = null,
    int? BaselineRank = null);

/// <summary>Provenance of an EPSS or KEV data set. Dates are those published inside the data, never the current time.</summary>
public sealed record SignalSourceInfo(string Source, string Digest, string? Version, string? Date, int Entries, int Skipped);

public sealed record SignalSources(SignalSourceInfo? Epss, SignalSourceInfo? Kev);

/// <summary>How the reachability verdicts of a ranking were made: the analyzer, the symbol maps, what it read, and the totals.</summary>
public sealed record RankReachInfo(
    ReachAnalyzerInfo? Analyzer,
    SymbolMapInfo SymbolMaps,
    ReachSourceInfo? Source,
    ReachSummary Summary);

/// <summary>
/// How the risk distributions were made. <c>Seed</c> is a decimal string (a 64-bit number does not survive JSON consumers that read
/// numbers as doubles). <c>Calibration</c> is "uncalibrated-defaults" for the built-in placeholder parameters, "custom" for a
/// parameters file; neither is a claim about real-world loss.
/// </summary>
public sealed record RiskModelInfo(
    int Samples,
    string Seed,
    string SeedSource,
    string RankBy,
    string Calibration,
    string ParametersDigest,
    DepRisk.Core.Risk.RiskParameters Parameters);

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
    IReadOnlyList<RankedFinding> Findings,
    RankReachInfo? Reach = null,
    RiskModelInfo? Model = null)
{
    public const int CurrentSchemaVersion = 1;

    /// <summary>Name of the method, used as baseline "B2" in the evaluation plan.</summary>
    public const string BaselineMethod = "baseline-kev-epss-cvss";

    public static readonly string[] BaselineOrdering = ["kev", "epss", "cvss", "severity", "id"];

    /// <summary>Name of the uncertainty-aware method: seeded Monte Carlo over Reach x Exploit x Impact.</summary>
    public const string RiskMethod = "risk-monte-carlo";
}

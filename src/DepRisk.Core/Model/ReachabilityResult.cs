namespace DepRisk.Core.Model;

/// <summary>One edge of the path from an entrypoint to a vulnerable symbol. Text fields come from the analyzer and are untrusted data.</summary>
public sealed record ReachPathEdge(string From, string To, string Kind, string? File, int? Line);

/// <summary>
/// The reachability of one finding. <c>Label</c> is reachable, possibly-reachable, unreachable, or unknown; <c>Reason</c> says why
/// (see <see cref="DepRisk.Core.Reach.ReachLabels"/>). <c>Path</c> is the shortest path to <c>Symbol</c> when there is one.
/// <c>SymbolSources</c> is where the symbol list comes from.
/// </summary>
public sealed record ReachVerdict(
    string Label,
    string Reason,
    string? Symbol,
    IReadOnlyList<ReachPathEdge> Path,
    IReadOnlyList<string> SymbolSources);

public sealed record ReachFinding(Finding Finding, ReachVerdict Reachability);

/// <summary>Which analyzer produced the verdicts: its name and version, and the SHA-256 of the executable.</summary>
public sealed record ReachAnalyzerInfo(string Name, string Version, string Sha256);

/// <summary>What the analyzer read. <c>SourceDigest</c> identifies exactly the files it analyzed.</summary>
public sealed record ReachSourceInfo(
    string SourceDigest,
    int Files,
    int FilesSkipped,
    int FilesWithErrors,
    int Methods,
    int Edges,
    int Entrypoints);

/// <summary>Where the symbol lists came from, without machine-specific paths.</summary>
public sealed record SymbolMapInfo(string Source, string Digest, int Files, int Entries);

public sealed record ReachSummary(int Reachable, int PossiblyReachable, int Unreachable, int Unknown);

/// <summary>
/// Result of <c>deprisk reach</c>. Public contract: schemas/reachability.v1.schema.json. Deterministic: no timestamps, no absolute
/// paths. <c>Analyzer</c> and <c>Source</c> are null when no analysis ran (nothing had symbols, or the ecosystem has no analyzer).
/// </summary>
public sealed record ReachabilityResult(
    int SchemaVersion,
    ToolInfo Tool,
    string Ecosystem,
    AdvisorySourceInfo Advisories,
    SymbolMapInfo SymbolMaps,
    ReachAnalyzerInfo? Analyzer,
    ReachSourceInfo? Source,
    ReachSummary Summary,
    IReadOnlyList<ReachFinding> Findings,
    IReadOnlyList<string> Diagnostics)
{
    public const int CurrentSchemaVersion = 1;
}

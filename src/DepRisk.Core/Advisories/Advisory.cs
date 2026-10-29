namespace DepRisk.Core.Advisories;

/// <summary>A severity entry as published, for example type "CVSS_V3" and a vector string. Not interpreted here.</summary>
public sealed record AdvisorySeverity(string Type, string Score);

/// <summary>One event of an OSV range: kind is "introduced", "fixed", "last_affected", or "limit".</summary>
public sealed record RangeEvent(string Kind, string Version);

/// <summary>An OSV range: "ECOSYSTEM" or "SEMVER" ranges are evaluated; other types (for example "GIT") are ignored.</summary>
public sealed record AffectedRange(string Type, IReadOnlyList<RangeEvent> Events);

/// <summary>An "affected" entry for one package: ranges and/or an explicit list of affected versions.</summary>
public sealed record AffectedPackage(
    string Ecosystem,
    string Name,
    IReadOnlyList<AffectedRange> Ranges,
    IReadOnlyList<string> Versions);

/// <summary>
/// The parts of an OSV advisory that DepRisk uses. Only entries for the NuGet ecosystem are kept.
/// </summary>
public sealed record Advisory(
    string Id,
    IReadOnlyList<string> Aliases,
    string? Summary,
    bool Withdrawn,
    IReadOnlyList<AdvisorySeverity> Scores,
    string? DatabaseSeverity,
    IReadOnlyList<AffectedPackage> Affected);

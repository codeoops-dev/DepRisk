using DepRisk.Core.Advisories;

namespace DepRisk.Core.Model;

/// <summary>Where the advisory data came from, without any machine-specific path.</summary>
public sealed record AdvisorySourceInfo(
    string Source,
    string Digest,
    int Count,
    int SkippedWithdrawn,
    int SkippedNotNuGet,
    int SkippedInvalid);

public sealed record FindingPackage(string Id, string Version);

/// <summary>
/// One place where an affected package is used. <c>ProjectFile</c> is the file that stands for the project in the repository:
/// the project file when it is known (see <see cref="ProjectGraph"/>), otherwise the assets file path. Relative, forward slashes.
/// </summary>
public sealed record FindingLocation(string Project, string Target, bool IsDirect, string? ProjectFile = null);

/// <summary>
/// One advisory that applies to one package version, with every project and target that uses that version.
/// Text fields come from the advisory database and are untrusted data.
/// </summary>
public sealed record Finding(
    string Id,
    IReadOnlyList<string> Aliases,
    string? Summary,
    string? Severity,
    IReadOnlyList<AdvisorySeverity> Scores,
    FindingPackage Package,
    IReadOnlyList<string> FixedVersions,
    IReadOnlyList<FindingLocation> Locations);

/// <summary>
/// Result of <c>deprisk match</c>. Public contract: schemas/findings.v1.schema.json.
/// Deterministic: no timestamps, no absolute paths.
/// </summary>
public sealed record FindingsResult(
    int SchemaVersion,
    ToolInfo Tool,
    string Ecosystem,
    AdvisorySourceInfo Advisories,
    int ProjectsScanned,
    int PackagesScanned,
    int PackagesSkipped,
    IReadOnlyList<Finding> Findings)
{
    public const int CurrentSchemaVersion = 1;
}

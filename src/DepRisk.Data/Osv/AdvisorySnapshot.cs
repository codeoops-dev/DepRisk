using DepRisk.Core.Advisories;

namespace DepRisk.Data.Osv;

/// <summary>
/// A set of advisories loaded from local files, with counts of what was skipped and a digest of the source
/// (so a result can always be tied to the exact data it was computed from).
/// </summary>
public sealed record AdvisorySnapshot(
    IReadOnlyList<Advisory> Advisories,
    string Source,
    string Digest,
    int SkippedWithdrawn,
    int SkippedNotNuGet,
    int SkippedInvalid,
    IReadOnlyList<string> InvalidSamples);

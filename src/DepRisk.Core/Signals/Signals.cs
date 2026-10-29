namespace DepRisk.Core.Signals;

/// <summary>EPSS: probability (0 to 1) of exploitation in the next 30 days, and the score's percentile.</summary>
public sealed record EpssScore(double Probability, double Percentile);

/// <summary>An EPSS data set as supplied (offline) plus its provenance.</summary>
public sealed record EpssData(
    IReadOnlyDictionary<string, EpssScore> Scores,
    string? ModelVersion,
    string? ScoreDate,
    string Source,
    string Digest,
    int SkippedRows,
    IReadOnlyList<string> SkippedSamples);

/// <summary>One entry of the CISA Known Exploited Vulnerabilities catalog.</summary>
public sealed record KevEntry(string CveId, string? DateAdded, bool KnownRansomwareUse);

/// <summary>A KEV catalog as supplied (offline) plus its provenance.</summary>
public sealed record KevData(
    IReadOnlyDictionary<string, KevEntry> Entries,
    string? CatalogVersion,
    string? DateReleased,
    string Source,
    string Digest,
    int SkippedEntries,
    IReadOnlyList<string> SkippedSamples);

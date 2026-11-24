namespace DepRisk.Core.Cvss;

/// <summary>Scores a vector string of any supported CVSS version: v3.0 and v3.1 (<see cref="CvssV3"/>) or v4.0 (<see cref="CvssV4"/>). v2 is not scored.</summary>
public static class CvssScorer
{
    public static bool TryScore(string? vector, out CvssScore? score) =>
        CvssV3.TryScore(vector, out score) || CvssV4.TryScore(vector, out score);
}

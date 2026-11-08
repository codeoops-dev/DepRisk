namespace DepRisk.Core.Bench;

/// <summary>
/// The measures of the evaluation (docs/benchmarks.md). Pure functions over a list of outcomes in the order a method presents its
/// findings (<c>true</c> = the finding turned out to be a positive). No IO, no randomness.
/// </summary>
public static class BenchMetrics
{
    /// <summary>
    /// Average precision: the mean, over all positives of the case, of the precision at the position where each positive is found. A
    /// positive that the method never presents (it was filtered out) contributes zero. Null when the case has no positive.
    /// </summary>
    public static double? AveragePrecision(IReadOnlyList<bool> presented, int totalPositives)
    {
        ArgumentNullException.ThrowIfNull(presented);

        if (totalPositives <= 0)
        {
            return null;
        }

        int hits = 0;
        double sum = 0;

        for (int i = 0; i < presented.Count; i++)
        {
            if (presented[i])
            {
                hits++;
                sum += (double)hits / (i + 1);
            }
        }

        return sum / totalPositives;
    }

    /// <summary>Share of all positives of the case found within the first <paramref name="k"/> presented findings. Null when the case has no positive.</summary>
    public static double? RecallAtK(IReadOnlyList<bool> presented, int totalPositives, int k)
    {
        ArgumentNullException.ThrowIfNull(presented);

        if (totalPositives <= 0)
        {
            return null;
        }

        return (double)CountPositives(presented, k) / totalPositives;
    }

    /// <summary>Share of positives among the first <paramref name="k"/> presented findings (k is capped at the number presented). Null when nothing is presented.</summary>
    public static double? PrecisionAtK(IReadOnlyList<bool> presented, int k)
    {
        ArgumentNullException.ThrowIfNull(presented);

        int taken = Math.Min(k, presented.Count);
        return taken == 0 ? null : (double)CountPositives(presented, taken) / taken;
    }

    /// <summary>
    /// How many findings a reader must go through, from the top, to have seen every positive of the case (the position of the last
    /// positive). Null if the method never presents some positive (it was filtered out) or the case has no positive.
    /// </summary>
    public static int? AlertsToFullRecall(IReadOnlyList<bool> presented, int totalPositives)
    {
        ArgumentNullException.ThrowIfNull(presented);

        if (totalPositives <= 0)
        {
            return null;
        }

        int hits = 0;

        for (int i = 0; i < presented.Count; i++)
        {
            if (presented[i] && ++hits == totalPositives)
            {
                return i + 1;
            }
        }

        return null;
    }

    private static int CountPositives(IReadOnlyList<bool> presented, int k)
    {
        int count = 0;

        for (int i = 0; i < Math.Min(k, presented.Count); i++)
        {
            if (presented[i])
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>Results are reported to six decimals, as everywhere else: more digits would only show last-bit differences between platforms.</summary>
    public static double Round(double value) => Math.Round(value, 6, MidpointRounding.ToEven);

    public static double? Round(double? value) => value is null ? null : Round(value.Value);
}

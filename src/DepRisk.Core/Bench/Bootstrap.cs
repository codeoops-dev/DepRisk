using DepRisk.Core.Risk;

namespace DepRisk.Core.Bench;

/// <summary>A closed interval, for example a 95% percentile bootstrap interval.</summary>
public sealed record Interval(double Low, double High);

/// <summary>
/// A seeded cluster bootstrap: the unit that is resampled is a case (a project), because findings of one project are not independent.
/// Same seed, same intervals. The percentile ranks use integer arithmetic (no floating-point rounding of ranks).
/// </summary>
public static class Bootstrap
{
    public const int MaxIterations = 20000;

    /// <summary>The case indices of each resample: <paramref name="iterations"/> arrays of <paramref name="cases"/> indices drawn with replacement.</summary>
    public static IReadOnlyList<int[]> Resamples(int cases, int iterations, ulong seed)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(cases, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaxIterations);

        Prng prng = new(Prng.StreamSeed(seed, "bench-bootstrap"));
        int[][] result = new int[iterations][];

        for (int i = 0; i < iterations; i++)
        {
            int[] draw = new int[cases];

            for (int j = 0; j < cases; j++)
            {
                draw[j] = (int)Math.Floor(prng.NextOpenUnit() * cases);
            }

            result[i] = draw;
        }

        return result;
    }

    /// <summary>The 95% percentile interval (nearest rank, 2.5% and 97.5%) of the values; null if there are none.</summary>
    public static Interval? Percentile95(IReadOnlyList<double> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        if (values.Count == 0)
        {
            return null;
        }

        double[] sorted = [.. values];
        Array.Sort(sorted);

        int n = sorted.Length;
        int lowRank = Math.Max(1, (n * 25 + 999) / 1000);
        int highRank = Math.Min(n, (n * 975 + 999) / 1000);

        return new Interval(BenchMetrics.Round(sorted[lowRank - 1]), BenchMetrics.Round(sorted[highRank - 1]));
    }
}

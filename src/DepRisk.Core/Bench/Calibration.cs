namespace DepRisk.Core.Bench;

/// <summary>One bin of a reliability table: the findings whose predicted probability fell in [Low, High) (the last bin includes 1).</summary>
public sealed record ReliabilityBin(double Low, double High, int Count, double? MeanPredicted, double? ObservedRate);

/// <summary>How well predicted probabilities match what happened: Brier score, log loss, expected calibration error, and the reliability table.</summary>
public sealed record CalibrationSummary(
    int Count,
    double? BaseRate,
    double? Brier,
    double? LogLoss,
    double? Ece,
    IReadOnlyList<ReliabilityBin> Bins);

/// <summary>Calibration of probabilities against binary outcomes (equal-width bins). Pure.</summary>
public static class Calibration
{
    public const int DefaultBins = 10;

    /// <summary>Probabilities are clipped to [epsilon, 1 - epsilon] for the log loss only; the value is part of the method (docs/benchmarks.md).</summary>
    public const double LogLossEpsilon = 1e-6;

    public static CalibrationSummary Summarize(IReadOnlyList<(double Predicted, bool Outcome)> pairs, int bins = DefaultBins)
    {
        ArgumentNullException.ThrowIfNull(pairs);
        ArgumentOutOfRangeException.ThrowIfLessThan(bins, 1);

        int[] counts = new int[bins];
        double[] predictedSums = new double[bins];
        int[] positives = new int[bins];
        double brier = 0;
        double logLoss = 0;
        int totalPositives = 0;

        foreach ((double p, bool outcome) in pairs)
        {
            if (double.IsNaN(p) || p < 0 || p > 1)
            {
                throw new ArgumentOutOfRangeException(nameof(pairs), "a predicted probability is outside [0, 1].");
            }

            int bin = Math.Min(bins - 1, (int)Math.Floor(p * bins));
            counts[bin]++;
            predictedSums[bin] += p;

            double y = outcome ? 1 : 0;

            if (outcome)
            {
                positives[bin]++;
                totalPositives++;
            }

            brier += (p - y) * (p - y);

            double clipped = Math.Clamp(p, LogLossEpsilon, 1 - LogLossEpsilon);
            logLoss -= outcome ? Math.Log(clipped) : Math.Log(1 - clipped);
        }

        int n = pairs.Count;
        List<ReliabilityBin> table = [];
        double ece = 0;

        for (int b = 0; b < bins; b++)
        {
            double low = (double)b / bins;
            double high = (double)(b + 1) / bins;

            if (counts[b] == 0)
            {
                table.Add(new ReliabilityBin(BenchMetrics.Round(low), BenchMetrics.Round(high), 0, null, null));
                continue;
            }

            double meanPredicted = predictedSums[b] / counts[b];
            double observed = (double)positives[b] / counts[b];
            ece += (double)counts[b] / n * Math.Abs(observed - meanPredicted);
            table.Add(new ReliabilityBin(BenchMetrics.Round(low), BenchMetrics.Round(high), counts[b], BenchMetrics.Round(meanPredicted), BenchMetrics.Round(observed)));
        }

        return n == 0
            ? new CalibrationSummary(0, null, null, null, null, table)
            : new CalibrationSummary(
                n,
                BenchMetrics.Round((double)totalPositives / n),
                BenchMetrics.Round(brier / n),
                BenchMetrics.Round(logLoss / n),
                BenchMetrics.Round(ece),
                table);
    }
}

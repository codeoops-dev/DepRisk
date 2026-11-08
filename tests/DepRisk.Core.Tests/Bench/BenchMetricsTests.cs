using DepRisk.Core.Bench;
using Xunit;

namespace DepRisk.Core.Tests.Bench;

public sealed class BenchMetricsTests
{
    [Fact]
    public void Average_precision_is_the_mean_of_the_precisions_at_each_positive()
    {
        // Positives found at positions 1 and 3: (1/1 + 2/3) / 2.
        Assert.Equal(0.833333, BenchMetrics.Round(BenchMetrics.AveragePrecision([true, false, true], 2)));
        Assert.Equal(1.0, BenchMetrics.AveragePrecision([true, true, false], 2));
    }

    [Fact]
    public void A_positive_the_method_never_presents_counts_as_zero()
    {
        // Two positives in the case, one filtered out: (1/1) / 2.
        Assert.Equal(0.5, BenchMetrics.AveragePrecision([true], 2));
        Assert.Equal(0.0, BenchMetrics.AveragePrecision([], 2));
    }

    [Fact]
    public void A_case_without_a_positive_has_no_average_precision_recall_or_alert_count()
    {
        Assert.Null(BenchMetrics.AveragePrecision([false, false], 0));
        Assert.Null(BenchMetrics.RecallAtK([false], 0, 1));
        Assert.Null(BenchMetrics.AlertsToFullRecall([false], 0));
    }

    [Fact]
    public void Recall_at_k_counts_positives_in_the_first_k_over_all_positives()
    {
        Assert.Equal(0.5, BenchMetrics.RecallAtK([false, true, true], 2, 2));
        Assert.Equal(1.0, BenchMetrics.RecallAtK([false, true, true], 2, 10));
        Assert.Equal(0.0, BenchMetrics.RecallAtK([false, true, true], 2, 1));

        // A filtered-out positive keeps recall below one however large k is.
        Assert.Equal(0.5, BenchMetrics.RecallAtK([true], 2, 10));
    }

    [Fact]
    public void Precision_at_k_caps_k_at_the_number_presented_and_is_null_for_nothing()
    {
        Assert.Equal(0.5, BenchMetrics.PrecisionAtK([true, false, true], 2));
        Assert.Equal(0.666667, BenchMetrics.Round(BenchMetrics.PrecisionAtK([true, false, true], 10)));
        Assert.Null(BenchMetrics.PrecisionAtK([], 3));
    }

    [Fact]
    public void Alerts_to_full_recall_is_the_position_of_the_last_positive()
    {
        Assert.Equal(3, BenchMetrics.AlertsToFullRecall([true, false, true], 2));
        Assert.Equal(3, BenchMetrics.AlertsToFullRecall([false, true, true, false], 2));
        Assert.Equal(1, BenchMetrics.AlertsToFullRecall([true, false], 1));
    }

    [Fact]
    public void Alerts_to_full_recall_is_null_when_a_positive_is_not_presented()
    {
        Assert.Null(BenchMetrics.AlertsToFullRecall([true], 2));
        Assert.Null(BenchMetrics.AlertsToFullRecall([], 1));
    }
}

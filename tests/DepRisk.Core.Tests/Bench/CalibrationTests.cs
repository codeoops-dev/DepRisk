using DepRisk.Core.Bench;
using Xunit;

namespace DepRisk.Core.Tests.Bench;

public sealed class CalibrationTests
{
    private static readonly (double, bool)[] Sample = [(0.1, false), (0.9, true), (0.5, true), (0.5, false)];

    [Fact]
    public void Brier_score_and_log_loss_follow_their_definitions()
    {
        CalibrationSummary s = Calibration.Summarize(Sample);

        Assert.Equal(4, s.Count);
        Assert.Equal(0.5, s.BaseRate);

        // (0.1^2 + 0.1^2 + 0.5^2 + 0.5^2) / 4
        Assert.Equal(0.13, s.Brier);

        // -(ln 0.9 + ln 0.9 + ln 0.5 + ln 0.5) / 4
        Assert.Equal(0.399254, s.LogLoss);
    }

    [Fact]
    public void Expected_calibration_error_weighs_each_bin_by_its_share()
    {
        CalibrationSummary s = Calibration.Summarize(Sample);

        // Bin 0.1: predicted 0.1, observed 0 (1/4 of the findings); bin 0.9: predicted 0.9, observed 1 (1/4); bin 0.5 is exact.
        Assert.Equal(0.05, s.Ece);
        Assert.Equal(10, s.Bins.Count);

        ReliabilityBin middle = s.Bins[5];
        Assert.Equal(2, middle.Count);
        Assert.Equal(0.5, middle.MeanPredicted);
        Assert.Equal(0.5, middle.ObservedRate);

        ReliabilityBin empty = s.Bins[3];
        Assert.Equal(0, empty.Count);
        Assert.Null(empty.MeanPredicted);
        Assert.Null(empty.ObservedRate);
    }

    [Fact]
    public void A_probability_of_one_lands_in_the_last_bin_and_the_log_loss_stays_finite()
    {
        CalibrationSummary s = Calibration.Summarize([(1.0, false), (0.0, true)]);

        Assert.Equal(1, s.Bins[9].Count);
        Assert.Equal(1, s.Bins[0].Count);
        Assert.True(double.IsFinite(s.LogLoss!.Value));
        Assert.Equal(13.815511, s.LogLoss);
    }

    [Fact]
    public void Nothing_to_summarize_gives_empty_bins_and_no_numbers()
    {
        CalibrationSummary s = Calibration.Summarize([]);

        Assert.Equal(0, s.Count);
        Assert.Null(s.Brier);
        Assert.Null(s.LogLoss);
        Assert.Null(s.Ece);
        Assert.Null(s.BaseRate);
        Assert.Equal(10, s.Bins.Count);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    [InlineData(double.NaN)]
    public void A_probability_outside_zero_to_one_is_refused(double p)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Calibration.Summarize([(p, true)]));
    }
}

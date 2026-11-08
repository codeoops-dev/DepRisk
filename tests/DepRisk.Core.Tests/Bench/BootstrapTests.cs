using DepRisk.Core.Bench;
using Xunit;

namespace DepRisk.Core.Tests.Bench;

public sealed class BootstrapTests
{
    [Fact]
    public void Resamples_have_the_requested_shape_and_stay_inside_the_cases()
    {
        IReadOnlyList<int[]> draws = Bootstrap.Resamples(5, 50, 7);

        Assert.Equal(50, draws.Count);
        Assert.All(draws, d =>
        {
            Assert.Equal(5, d.Length);
            Assert.All(d, i => Assert.True(i >= 0 && i < 5));
        });
    }

    [Fact]
    public void The_same_seed_gives_the_same_resamples_and_another_seed_does_not()
    {
        IReadOnlyList<int[]> a = Bootstrap.Resamples(6, 20, 1);
        IReadOnlyList<int[]> b = Bootstrap.Resamples(6, 20, 1);
        IReadOnlyList<int[]> c = Bootstrap.Resamples(6, 20, 2);

        Assert.Equal(a.Select(d => string.Join(",", d)).ToArray(), b.Select(d => string.Join(",", d)).ToArray());
        Assert.NotEqual(a.Select(d => string.Join(",", d)).ToArray(), c.Select(d => string.Join(",", d)).ToArray());
    }

    [Fact]
    public void Every_case_gets_drawn_sometimes()
    {
        HashSet<int> seen = [.. Bootstrap.Resamples(4, 200, 3).SelectMany(d => d)];
        Assert.Equal(4, seen.Count);
    }

    [Fact]
    public void Too_many_or_no_iterations_and_no_cases_are_refused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Bootstrap.Resamples(3, Bootstrap.MaxIterations + 1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bootstrap.Resamples(3, 0, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bootstrap.Resamples(0, 10, 1));
    }

    [Fact]
    public void The_interval_uses_nearest_ranks_at_two_and_a_half_and_ninety_seven_and_a_half_percent()
    {
        double[] hundred = Enumerable.Range(1, 100).Select(i => (double)i).ToArray();
        Interval? interval = Bootstrap.Percentile95(hundred);

        // ceil(100 x 0.025) = 3 and ceil(100 x 0.975) = 98: integer ranks, no floating-point surprise.
        Assert.Equal(3.0, interval!.Low);
        Assert.Equal(98.0, interval.High);

        double[] forty = Enumerable.Range(1, 40).Select(i => (double)i).ToArray();
        Assert.Equal(1.0, Bootstrap.Percentile95(forty)!.Low);
        Assert.Equal(39.0, Bootstrap.Percentile95(forty)!.High);
    }

    [Fact]
    public void The_interval_does_not_depend_on_the_order_of_the_values_and_handles_one_value_or_none()
    {
        Assert.Equal(Bootstrap.Percentile95([3.0, 1.0, 2.0]), Bootstrap.Percentile95([1.0, 2.0, 3.0]));
        Assert.Equal(new Interval(4.0, 4.0), Bootstrap.Percentile95([4.0]));
        Assert.Null(Bootstrap.Percentile95([]));
    }
}

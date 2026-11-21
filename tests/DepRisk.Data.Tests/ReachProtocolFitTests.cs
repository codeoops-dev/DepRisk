using DepRisk.Core.Reach;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>ADR 0026: an analyzer answer whose label and reason contradict each other is refused as a whole, never believed in part.</summary>
public sealed class ReachProtocolFitTests
{
    private static string Request() =>
        ReachProtocol.BuildRequest("/src", "auto", [], [new ReachTarget("k1", ["A.B.C"], true)]);

    [Fact]
    public void Every_pair_that_fits_is_accepted()
    {
        foreach (string label in ReachLabels.AllLabels)
        {
            foreach (string reason in ReachLabels.ReasonsFor(label))
            {
                AnalyzerOutput output = ReachProtocol.ParseResult(FakeAnalyzer.Result(Request(), label, reason), ["k1"]);

                Assert.Equal(label, output.Verdicts["k1"].Label);
                Assert.Equal(reason, output.Verdicts["k1"].Reason);
            }
        }
    }

    [Fact]
    public void Every_pair_that_does_not_fit_is_an_error()
    {
        int refused = 0;

        foreach (string label in ReachLabels.AllLabels)
        {
            foreach (string reason in ReachLabels.AnalyzerReasons.Where(r => !ReachLabels.Fits(label, r)))
            {
                AnalyzerException error = Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(FakeAnalyzer.Result(Request(), label, reason), ["k1"]));

                Assert.Contains("do not fit together", error.Message);
                refused++;
            }
        }

        Assert.Equal(27, refused);
    }

    [Fact]
    public void An_unreachable_that_says_a_static_path_exists_is_refused_whatever_else_it_carries()
    {
        string result = FakeAnalyzer.Result(Request(), "unreachable", "static-path", symbol: "A.B.C", path: """[{"from":"P.Main","to":"A.B.C","kind":"static","file":"P.cs","line":7}]""");

        Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(result, ["k1"]));
    }
}

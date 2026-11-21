using DepRisk.Core.Reach;
using Xunit;

namespace DepRisk.Core.Tests;

public sealed class ReachLabelFitTests
{
    [Fact]
    public void Each_label_has_exactly_the_reasons_the_analyzer_gives_with_it()
    {
        Assert.Equal(new[] { "static-path" }, ReachLabels.ReasonsFor(ReachLabels.Reachable));
        Assert.Equal(new[] { "dynamic-path" }, ReachLabels.ReasonsFor(ReachLabels.PossiblyReachable));
        Assert.Equal(new[] { "no-path" }, ReachLabels.ReasonsFor(ReachLabels.Unreachable));
        Assert.Equal(
            new[] { "no-symbols", "no-entrypoints", "symbol-list-incomplete", "incomplete-analysis", "unresolved-reflection", "unresolved-receiver" },
            ReachLabels.ReasonsFor(ReachLabels.Unknown));
    }

    [Fact]
    public void Every_analyzer_reason_belongs_to_exactly_one_label()
    {
        foreach (string reason in ReachLabels.AnalyzerReasons)
        {
            Assert.Equal(1, ReachLabels.AllLabels.Count(label => ReachLabels.Fits(label, reason)));
        }
    }

    [Fact]
    public void Of_all_label_and_reason_pairs_only_the_nine_that_make_sense_fit()
    {
        int fitting = 0;

        foreach (string label in ReachLabels.AllLabels)
        {
            foreach (string reason in ReachLabels.AnalyzerReasons)
            {
                if (ReachLabels.Fits(label, reason))
                {
                    fitting++;
                }
            }
        }

        Assert.Equal(9, fitting);
        Assert.False(ReachLabels.Fits(ReachLabels.Unreachable, ReachLabels.StaticPath));
        Assert.False(ReachLabels.Fits(ReachLabels.Reachable, ReachLabels.NoPath));
        Assert.False(ReachLabels.Fits(ReachLabels.Unreachable, ReachLabels.SymbolListIncomplete));
        Assert.False(ReachLabels.Fits(ReachLabels.Reachable, ReachLabels.DynamicPath));
    }

    [Fact]
    public void The_reasons_only_the_cli_adds_and_unknown_names_fit_no_label()
    {
        foreach (string label in ReachLabels.AllLabels)
        {
            Assert.False(ReachLabels.Fits(label, ReachLabels.TransitivePackage));
            Assert.False(ReachLabels.Fits(label, ReachLabels.NoAnalyzerForEcosystem));
            Assert.False(ReachLabels.Fits(label, "made-up"));
        }

        Assert.Empty(ReachLabels.ReasonsFor("made-up"));
        Assert.False(ReachLabels.Fits("made-up", ReachLabels.NoPath));
    }
}

using DepRisk.Core.Model;
using DepRisk.Core.Reach;
using Xunit;

namespace DepRisk.Core.Tests;

public sealed class SymbolCheckTests
{
    private static Finding Make(string id, string package, string[]? aliases = null, bool direct = true) =>
        new(id, aliases ?? [], null, null, [], new FindingPackage(package, "1.0.0"), [], [new FindingLocation("App", "net10.0", direct)]);

    private static SymbolSet Set(string advisory, string package, bool complete, string language = SymbolLanguages.CSharp) =>
        new(advisory, package, language == SymbolLanguages.JavaScript ? ["*"] : ["A.B.C"], complete, ["test"], language);

    private static SymbolCheckResult Check(Finding[] findings, params SymbolSet[] sets) =>
        SymbolCheck.Evaluate(findings, new SymbolMap(sets), SymbolLanguages.CSharp);

    [Fact]
    public void An_entry_that_matches_a_finding_applies()
    {
        SymbolCheckResult result = Check([Make("GHSA-1", "Lib.A")], Set("GHSA-1", "Lib.A", true));

        SymbolEntryCheck entry = Assert.Single(result.Entries);
        Assert.Equal(SymbolEntryStatus.Applies, entry.Status);
        Assert.True(entry.Direct);
        Assert.Equal(1, result.Applies);
        Assert.Equal(0, result.Unused);
        Assert.Equal(0, result.Missing);
    }

    [Fact]
    public void An_entry_matches_by_alias_and_ignoring_case()
    {
        SymbolCheckResult result = Check([Make("GHSA-1", "Lib.A", ["CVE-7"])], Set("cve-7", "lib.a", false));

        Assert.Equal(SymbolEntryStatus.Applies, Assert.Single(result.Entries).Status);
        Assert.Equal(1, result.Incomplete);
    }

    [Fact]
    public void An_entry_for_a_package_or_advisory_the_project_does_not_have_is_unused()
    {
        SymbolCheckResult result = Check(
            [Make("GHSA-1", "Lib.A")],
            Set("GHSA-1", "Other.Lib", true),
            Set("GHSA-gone", "Lib.A", true));

        Assert.All(result.Entries, e => Assert.Equal(SymbolEntryStatus.Unused, e.Status));
        Assert.Equal(2, result.Unused);
        Assert.Equal(1, result.Missing);
    }

    [Fact]
    public void Complete_on_a_transitive_only_package_is_counted()
    {
        SymbolCheckResult result = Check([Make("GHSA-1", "Lib.A", direct: false)], Set("GHSA-1", "Lib.A", true));

        Assert.Equal(1, result.CompleteButTransitive);
        Assert.Equal(0, result.Incomplete);
    }

    [Fact]
    public void Entries_of_the_other_language_are_counted_not_judged()
    {
        SymbolCheckResult result = Check([Make("GHSA-1", "lib-a")], Set("GHSA-1", "lib-a", true, SymbolLanguages.JavaScript));

        Assert.Empty(result.Entries);
        Assert.Equal(1, result.IgnoredOtherLanguage);
        Assert.Equal(1, result.Missing);
    }

    [Fact]
    public void Pairs_without_an_entry_are_missing_and_unwritable_ones_are_not_counted_as_missing()
    {
        SymbolCheckResult result = Check([Make("GHSA-1", "Lib.A"), Make("GHSA-2", "Lib B")]);

        Assert.Equal(1, result.Missing);
        Assert.Equal(1, result.Unwritable);
    }

    [Fact]
    public void The_gate_names_the_conditions_that_hold_in_a_fixed_order()
    {
        SymbolCheckResult result = Check(
            [Make("GHSA-1", "Lib.A"), Make("GHSA-2", "Lib.B")],
            Set("GHSA-1", "Lib.A", false),
            Set("GHSA-gone", "Gone", true));

        Assert.Equal(new[] { "missing: 1", "incomplete: 1", "unused: 1" }, SymbolCheck.Tripped(result, SymbolCheck.ParseGate("unused, incomplete,missing")).ToArray());
        Assert.Equal(new[] { "incomplete: 1" }, SymbolCheck.Tripped(result, SymbolCheck.ParseGate("incomplete")).ToArray());
    }

    [Fact]
    public void A_gate_that_does_not_hold_is_empty()
    {
        SymbolCheckResult result = Check([Make("GHSA-1", "Lib.A")], Set("GHSA-1", "Lib.A", true));

        Assert.Empty(SymbolCheck.Tripped(result, SymbolCheck.ParseGate("missing,incomplete,unused")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("reachable")]
    [InlineData("missing,bogus")]
    [InlineData("missing,,unused")]
    public void An_unknown_or_empty_gate_term_is_an_input_error(string expression)
    {
        Assert.Throws<InvalidInputException>(() => SymbolCheck.ParseGate(expression));
    }

    [Fact]
    public void An_unknown_language_is_refused()
    {
        Assert.Throws<ArgumentException>(() => SymbolCheck.Evaluate([], new SymbolMap([]), "cobol"));
    }
}

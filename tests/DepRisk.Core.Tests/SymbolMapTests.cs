using DepRisk.Core.Reach;
using Xunit;

namespace DepRisk.Core.Tests;

public class SymbolMapTests
{
    [Theory]
    [InlineData("Newtonsoft.Json.JsonConvert.DeserializeObject")]
    [InlineData("A.B")]
    [InlineData("A.B.#ctor")]
    [InlineData("Ns.Type.*")]
    [InlineData("_a._b._c")]
    [InlineData("A1.B2.C3")]
    public void Valid_symbols(string symbol) => Assert.True(SymbolSyntax.IsValid(symbol));

    [Theory]
    [InlineData("")]
    [InlineData("Member")]
    [InlineData("A..B")]
    [InlineData(".A.B")]
    [InlineData("A.B.")]
    [InlineData("A.*.B")]
    [InlineData("A.#ctor.B")]
    [InlineData("1A.B")]
    [InlineData("A.B C")]
    [InlineData("A.B<T>")]
    [InlineData("A.B(int)")]
    [InlineData("A.B\u001b[31m")]
    [InlineData("Ä.B")]
    public void Invalid_symbols(string symbol) => Assert.False(SymbolSyntax.IsValid(symbol));

    [Fact]
    public void Null_and_over_long_symbols_are_invalid()
    {
        Assert.False(SymbolSyntax.IsValid(null));
        Assert.False(SymbolSyntax.IsValid("A." + new string('b', SymbolSyntax.MaxLength)));
    }

    private static SymbolSet Set(string advisory, string package, bool complete, string source, params string[] symbols) => new(advisory, package, symbols, complete, [source]);

    [Fact]
    public void An_entry_is_found_by_advisory_id_or_any_alias_and_package_ignoring_case()
    {
        SymbolMap map = new([Set("CVE-2099-1", "Newtonsoft.Json", true, "s", "A.B.C")]);

        Assert.NotNull(map.Find(["GHSA-xxxx", "cve-2099-1"], "newtonsoft.JSON"));
        Assert.Null(map.Find(["GHSA-xxxx"], "Newtonsoft.Json"));
        Assert.Null(map.Find(["CVE-2099-1"], "Other.Package"));
    }

    [Fact]
    public void Entries_for_the_same_flaw_are_merged_conservatively()
    {
        SymbolMap map = new(
        [
            Set("GHSA-1", "P", true, "curator-a", "A.B.C", "A.B.D"),
            Set("ghsa-1", "p", false, "curator-b", "A.B.D", "A.B.E"),
        ]);

        SymbolSet merged = map.Find(["GHSA-1"], "P")!;

        Assert.Equal(new[] { "A.B.C", "A.B.D", "A.B.E" }, merged.Symbols.ToArray());
        Assert.False(merged.Complete);   // complete only if every entry claims it
        Assert.Equal(new[] { "curator-a", "curator-b" }, merged.Sources.ToArray());
        Assert.Equal(1, map.Count);
    }

    [Fact]
    public void Two_ids_of_one_finding_are_merged_too()
    {
        SymbolMap map = new([Set("GHSA-1", "P", true, "s1", "A.B.C"), Set("CVE-2099-1", "P", true, "s2", "A.B.D")]);

        SymbolSet merged = map.Find(["GHSA-1", "CVE-2099-1"], "P")!;

        Assert.Equal(new[] { "A.B.C", "A.B.D" }, merged.Symbols.ToArray());
        Assert.True(merged.Complete);
    }

    [Fact]
    public void Labels_are_ordered_by_urgency()
    {
        string[] ordered = [ReachLabels.Reachable, ReachLabels.PossiblyReachable, ReachLabels.Unknown, ReachLabels.Unreachable];

        Assert.Equal(ordered, ReachLabels.AllLabels.OrderBy(ReachLabels.Priority).ToArray());
    }
}

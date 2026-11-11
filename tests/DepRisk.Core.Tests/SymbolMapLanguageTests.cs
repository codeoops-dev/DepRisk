using DepRisk.Core.Reach;
using Xunit;

namespace DepRisk.Core.Tests;

public sealed class SymbolMapLanguageTests
{
    private static SymbolSet Set(string advisory, string package, string symbol, string language, bool complete = true) =>
        new(advisory, package, [symbol], complete, ["test"], language);

    [Fact]
    public void A_set_is_found_only_for_its_own_language()
    {
        SymbolMap map = new([Set("GHSA-1", "Pkg", "A.B.C", SymbolLanguages.CSharp), Set("GHSA-1", "pkg", "pkg::run", SymbolLanguages.JavaScript)]);

        Assert.Equal("A.B.C", map.Find(["GHSA-1"], "Pkg")!.Symbols.Single());
        Assert.Equal("A.B.C", map.Find(["GHSA-1"], "Pkg", SymbolLanguages.CSharp)!.Symbols.Single());
        Assert.Equal("pkg::run", map.Find(["ghsa-1"], "PKG", SymbolLanguages.JavaScript)!.Symbols.Single());
        Assert.Equal(2, map.Count);
        Assert.Equal(1, map.CountFor(SymbolLanguages.CSharp));
        Assert.Equal(1, map.CountFor(SymbolLanguages.JavaScript));
    }

    [Fact]
    public void Entries_of_the_other_language_are_not_merged_in()
    {
        SymbolMap map = new([Set("GHSA-1", "x", "x::a", SymbolLanguages.JavaScript), Set("GHSA-1", "x", "N.T.M", SymbolLanguages.CSharp, complete: false)]);

        SymbolSet js = map.Find(["GHSA-1"], "x", SymbolLanguages.JavaScript)!;
        Assert.True(js.Complete);
        Assert.Equal(["x::a"], js.Symbols.ToArray());
        Assert.Equal(SymbolLanguages.JavaScript, js.Language);
    }

    [Fact]
    public void Two_entries_of_one_language_still_merge_conservatively()
    {
        SymbolMap map = new([Set("GHSA-1", "x", "x::a", SymbolLanguages.JavaScript), Set("GHSA-1", "x", "x::b", SymbolLanguages.JavaScript, complete: false)]);

        SymbolSet merged = map.Find(["GHSA-1"], "x", SymbolLanguages.JavaScript)!;
        Assert.Equal(["x::a", "x::b"], merged.Symbols.ToArray());
        Assert.False(merged.Complete);
        Assert.Equal(SymbolLanguages.JavaScript, merged.Language);
    }

    [Fact]
    public void Nothing_is_found_for_a_language_that_has_no_entry()
    {
        SymbolMap map = new([Set("GHSA-1", "x", "N.T.M", SymbolLanguages.CSharp)]);

        Assert.Null(map.Find(["GHSA-1"], "x", SymbolLanguages.JavaScript));
        Assert.Equal(0, map.CountFor(SymbolLanguages.JavaScript));
    }
}

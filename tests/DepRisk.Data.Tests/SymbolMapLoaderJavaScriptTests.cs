using DepRisk.Core;
using DepRisk.Core.Reach;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class SymbolMapLoaderJavaScriptTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-symbols-js-" + Guid.NewGuid().ToString("N"));

    public SymbolMapLoaderJavaScriptTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Put(string name, string content)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Map(string entries, string language = "javascript") =>
        $$"""{ "schemaVersion": 1, "language": "{{language}}", "entries": [ {{entries}} ] }""";

    private static string Entry(string package = "example-lib", string symbols = "\"parse\"", string advisory = "GHSA-1", string complete = "true") =>
        $$"""{ "advisory": "{{advisory}}", "package": "{{package}}", "symbols": [ {{symbols}} ], "complete": {{complete}}, "source": "test" }""";

    private static void Refused(string path, string expectedPart)
    {
        InvalidInputException ex = Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(path));
        Assert.Contains(expectedPart, ex.Message);
    }

    [Fact]
    public void Relative_symbols_are_composed_with_the_package_of_the_entry()
    {
        LoadedSymbolMaps loaded = SymbolMapLoader.Load(Put("m.json", Map(Entry(symbols: "\"parse\", \"Parser.*\", \"*\"", package: "@scope/pkg"))));

        SymbolSet set = loaded.Map.Find(["GHSA-1"], "@scope/pkg", SymbolLanguages.JavaScript)!;

        Assert.Equal(["@scope/pkg::*", "@scope/pkg::Parser.*", "@scope/pkg::parse"], set.Symbols.ToArray());
        Assert.Equal(SymbolLanguages.JavaScript, set.Language);
        Assert.True(set.Complete);
        Assert.Null(loaded.Map.Find(["GHSA-1"], "@scope/pkg"));
    }

    [Fact]
    public void Full_symbols_may_name_a_subpath_of_the_package()
    {
        LoadedSymbolMaps loaded = SymbolMapLoader.Load(Put("m.json", Map(Entry(package: "lodash", symbols: "\"lodash::template\", \"lodash/fp::map\""))));

        Assert.Equal(["lodash/fp::map", "lodash::template"], loaded.Map.Find(["GHSA-1"], "lodash", SymbolLanguages.JavaScript)!.Symbols.ToArray());
    }

    [Theory]
    [InlineData("\"other::x\"")]
    [InlineData("\"lodash-es::x\"")]
    [InlineData("\"a..b\"")]
    [InlineData("\"1a\"")]
    [InlineData("\"A.B.C::\"")]
    [InlineData("42")]
    public void A_symbol_that_is_not_a_path_of_this_package_is_refused_by_name(string symbol)
    {
        Refused(Put("m.json", Map(Entry(package: "lodash", symbols: symbol))), "is not a valid symbol for 'lodash'");
    }

    [Theory]
    [InlineData("../x")]
    [InlineData("a b")]
    [InlineData("./local")]
    public void A_package_must_be_an_npm_name(string package)
    {
        Refused(Put("m.json", Map(Entry(package: package))), "invalid 'package'");
    }

    [Fact]
    public void A_csharp_map_still_refuses_javascript_looking_symbols_and_scoped_names()
    {
        Refused(Put("a.json", Map(Entry(package: "P", symbols: "\"lodash::template\""), "csharp")), "is not a valid symbol");
        Refused(Put("b.json", Map(Entry(package: "@scope/pkg", symbols: "\"A.B.C\""), "csharp")), "invalid 'package'");
    }

    [Fact]
    public void Only_csharp_and_javascript_are_languages()
    {
        Refused(Put("a.json", Map("", "typescript")), "'language' must be \"csharp\" or \"javascript\"");
        Refused(Put("b.json", """{ "schemaVersion": 1, "entries": [] }"""), "'language' must be");
    }

    [Fact]
    public void A_directory_may_hold_maps_of_both_languages()
    {
        Put("cs.json", Map(Entry(package: "Newtonsoft.Json", symbols: "\"Newtonsoft.Json.JsonConvert.DeserializeObject\""), "csharp"));
        Put("js.json", Map(Entry(package: "example-lib")));

        LoadedSymbolMaps loaded = SymbolMapLoader.Load(_root);

        Assert.Equal(2, loaded.Info.Files);
        Assert.Equal(2, loaded.Info.Entries);
        Assert.Equal(1, loaded.Map.CountFor(SymbolLanguages.CSharp));
        Assert.Equal(1, loaded.Map.CountFor(SymbolLanguages.JavaScript));
    }

    [Fact]
    public void The_fixture_map_for_npm_loads()
    {
        LoadedSymbolMaps loaded = SymbolMapLoader.Load(Put("npm-example.json", NpmFixtures.ReadReachNpm("symbols/npm-example.json")));

        Assert.Equal(4, loaded.Info.Entries);
        Assert.Equal(["deep-lib::*"], loaded.Map.Find(["DEPRISK-NPM-0003"], "deep-lib", SymbolLanguages.JavaScript)!.Symbols.ToArray());
    }
}

using DepRisk.Core;
using DepRisk.Core.Reach;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class SymbolMapLoaderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-symbols-" + Guid.NewGuid().ToString("N"));

    public SymbolMapLoaderTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Put(string name, string content)
    {
        string path = Path.Combine(_root, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Map(string entries, string language = "csharp", int version = 1) =>
        $$"""{ "schemaVersion": {{version}}, "language": "{{language}}", "entries": [ {{entries}} ] }""";

    private static string Entry(string advisory = "GHSA-1", string package = "P", string symbols = "\"A.B.C\"", string complete = "true", string source = "test") =>
        $$"""{ "advisory": "{{advisory}}", "package": "{{package}}", "symbols": [ {{symbols}} ], "complete": {{complete}}, "source": "{{source}}" }""";

    [Fact]
    public void The_fixture_map_loads_with_a_digest_and_no_path_in_it()
    {
        string path = Put("example.json", NpmFixtures.ReadReach("symbols/example.json"));

        LoadedSymbolMaps loaded = SymbolMapLoader.Load(path);

        Assert.Equal("example.json", loaded.Info.Source);
        Assert.Equal(1, loaded.Info.Files);
        Assert.Equal(2, loaded.Info.Entries);
        Assert.True(Digest.IsSha256Hex(loaded.Info.Digest));
        Assert.False(loaded.Info.Source.Contains(_root, StringComparison.Ordinal));

        SymbolSet set = loaded.Map.Find(["CVE-2099-0001"], "Newtonsoft.Json")!;
        Assert.Equal(new[] { "Newtonsoft.Json.JsonConvert.DeserializeObject" }, set.Symbols.ToArray());
        Assert.False(set.Complete);
        Assert.Contains("example only", set.Sources[0]);
    }

    [Fact]
    public void A_directory_is_read_recursively_in_a_fixed_order_and_the_digest_is_stable()
    {
        Put("b/two.json", Map(Entry("GHSA-2", symbols: "\"A.B.D\"")));
        Put("a/one.json", Map(Entry("GHSA-1")));
        Put("a/notes.txt", "not a map");

        LoadedSymbolMaps first = SymbolMapLoader.Load(_root);
        LoadedSymbolMaps second = SymbolMapLoader.Load(_root);

        Assert.Equal(2, first.Info.Files);
        Assert.Equal(2, first.Info.Entries);
        Assert.Equal(first.Info.Digest, second.Info.Digest);
        Assert.NotNull(first.Map.Find(["GHSA-1"], "P"));
        Assert.NotNull(first.Map.Find(["GHSA-2"], "P"));
    }

    [Fact]
    public void Changing_a_file_changes_the_digest()
    {
        string path = Put("m.json", Map(Entry()));
        string before = SymbolMapLoader.Load(path).Info.Digest;

        File.WriteAllText(path, Map(Entry(symbols: "\"A.B.C\", \"A.B.D\"")));

        Assert.NotEqual(before, SymbolMapLoader.Load(path).Info.Digest);
    }

    [Fact]
    public void The_same_symbols_are_deduplicated_and_sorted()
    {
        LoadedSymbolMaps loaded = SymbolMapLoader.Load(Put("m.json", Map(Entry(symbols: "\"A.B.Z\", \"A.B.C\", \"A.B.C\""))));

        Assert.Equal(new[] { "A.B.C", "A.B.Z" }, loaded.Map.Find(["GHSA-1"], "P")!.Symbols.ToArray());
    }

    [Theory]
    [InlineData("{ nope", "not valid JSON")]
    [InlineData("[]", "missing 'schemaVersion'")]
    [InlineData("""{ "language": "csharp", "entries": [] }""", "missing 'schemaVersion'")]
    [InlineData("""{ "schemaVersion": 2, "language": "csharp", "entries": [] }""", "unsupported schemaVersion 2")]
    [InlineData("""{ "schemaVersion": 1, "entries": [] }""", "'language' must be \"csharp\"")]
    [InlineData("""{ "schemaVersion": 1, "language": "java", "entries": [] }""", "'language' must be \"csharp\"")]
    [InlineData("""{ "schemaVersion": 1, "language": "csharp" }""", "'entries' must be an array")]
    [InlineData("""{ "schemaVersion": 1, "language": "csharp", "entries": [ 5 ] }""", "entry 0 is not an object")]
    public void A_file_that_is_not_a_symbol_map_is_rejected_with_the_reason(string json, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(Put("m.json", json)));

        Assert.Contains("m.json", error.Message);
        Assert.Contains(expected, error.Message);
    }

    [Fact]
    public void A_missing_complete_is_an_error_because_there_is_no_default()
    {
        string entry = """{ "advisory": "GHSA-1", "package": "P", "symbols": ["A.B.C"], "source": "test" }""";

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(Put("m.json", Map(entry))));

        Assert.Contains("needs 'complete': true or false", error.Message);
    }

    [Theory]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "symbols": ["A.B.C"], "complete": "yes", "source": "t" }""", "needs 'complete'")]
    [InlineData("""{ "advisory": "", "package": "P", "symbols": ["A.B.C"], "complete": true, "source": "t" }""", "non-empty 'advisory'")]
    [InlineData("""{ "advisory": "GHSA 1", "package": "P", "symbols": ["A.B.C"], "complete": true, "source": "t" }""", "invalid 'advisory'")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P/Q", "symbols": ["A.B.C"], "complete": true, "source": "t" }""", "invalid 'package'")]
    [InlineData("""{ "advisory": "GHSA-1", "symbols": ["A.B.C"], "complete": true, "source": "t" }""", "non-empty 'package'")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "symbols": ["A.B.C"], "complete": true }""", "non-empty 'source'")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "symbols": ["A.B.C"], "complete": true, "source": "a\u001b[31m" }""", "invalid 'source'")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "complete": true, "source": "t" }""", "needs a 'symbols' array")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "symbols": [], "complete": true, "source": "t" }""", "'symbols' is empty")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "symbols": ["Member"], "complete": true, "source": "t" }""", "not a valid symbol")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "symbols": [5], "complete": true, "source": "t" }""", "not a valid symbol")]
    [InlineData("""{ "advisory": "GHSA-1", "package": "P", "symbols": ["A.B\u001b[2J"], "complete": true, "source": "t" }""", "not a valid symbol")]
    public void A_bad_entry_is_rejected_naming_the_entry_and_never_echoing_control_characters(string entry, string expected)
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(Put("m.json", Map(entry))));

        Assert.Contains("m.json: entry 0", error.Message);
        Assert.Contains(expected, error.Message);
        Assert.False(error.Message.Contains('\u001b'));
    }

    [Fact]
    public void The_entry_number_in_the_message_is_the_bad_one()
    {
        InvalidInputException error = Assert.Throws<InvalidInputException>(
            () => SymbolMapLoader.Load(Put("m.json", Map(Entry() + "," + Entry() + "," + Entry(symbols: "\"bad\"")))));

        Assert.Contains("entry 2", error.Message);
    }

    [Fact]
    public void Too_deep_and_too_large_files_are_rejected()
    {
        string deep = new string('[', 40) + new string(']', 40);

        Assert.Contains("not valid JSON", Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(Put("deep.json", deep))).Message);

        string big = Put("big.json", Map(Entry()));
        using (FileStream stream = File.OpenWrite(big))
        {
            stream.SetLength(SymbolMapLoader.MaxFileBytes + 1);
        }

        Assert.Contains("larger than", Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(big)).Message);
    }

    [Fact]
    public void A_path_that_does_not_exist_or_a_directory_without_maps_is_reported()
    {
        Assert.Contains("not found", Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(Path.Combine(_root, "nope"))).Message);

        string empty = Path.Combine(_root, "empty");
        Directory.CreateDirectory(empty);
        Assert.Contains("no .json symbol map files", Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(empty)).Message);
    }

    [Fact]
    public void One_bad_file_among_good_ones_fails_the_whole_load()
    {
        Put("good.json", Map(Entry()));
        Put("bad.json", "{ nope");

        // A symbol list that could not be read must never quietly become "no symbols known".
        Assert.Contains("bad.json", Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(_root)).Message);
    }
}

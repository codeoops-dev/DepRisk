using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

public class ReachProtocolTests
{
    private static string Request(params string[] keys) =>
        ReachProtocol.BuildRequest("/src", "auto", [], keys.Select(k => new ReachTarget(k, ["A.B.C"], true)).ToList());

    [Fact]
    public void The_request_follows_the_protocol()
    {
        string json = ReachProtocol.BuildRequest("C:\\src", "public-api", ["App.Worker.Run"], [new ReachTarget("GHSA-1|P", ["A.B.C", "A.B.*"], false)]);

        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(json);
        System.Text.Json.JsonElement root = document.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("C:\\src", root.GetProperty("root").GetString());
        Assert.Equal("public-api", root.GetProperty("entrypoints").GetProperty("mode").GetString());
        Assert.Equal("App.Worker.Run", root.GetProperty("entrypoints").GetProperty("explicit")[0].GetString());
        System.Text.Json.JsonElement target = root.GetProperty("targets")[0];
        Assert.Equal("GHSA-1|P", target.GetProperty("key").GetString());
        Assert.False(target.GetProperty("complete").GetBoolean());
        Assert.Equal(2, target.GetProperty("symbols").GetArrayLength());
    }

    [Fact]
    public void A_good_result_is_parsed()
    {
        string request = Request("k1", "k2");
        string result = FakeAnalyzer.Result(request, "reachable", "static-path", symbol: "A.B.C", path: """[{"from":"P.Main","to":"A.B.C","kind":"static","file":"P.cs","line":7}]""");

        AnalyzerOutput output = ReachProtocol.ParseResult(result, ["k1", "k2"]);

        Assert.Equal("deprisk-reach", output.AnalyzerName);
        Assert.Equal("9.9.9", output.AnalyzerVersion);
        Assert.Equal(new string('a', 64), output.SourceDigest);
        Assert.Equal(3, output.Source.Files);
        AnalyzerVerdict verdict = output.Verdicts["k1"];
        Assert.Equal("reachable", verdict.Label);
        Assert.Equal("A.B.C", verdict.Symbol);
        Assert.Equal(new DepRisk.Core.Model.ReachPathEdge("P.Main", "A.B.C", "static", "P.cs", 7), Assert.Single(verdict.Path));
    }

    private static string Replace(string json, string from, string to) => json.Replace(from, to, StringComparison.Ordinal);

    [Fact]
    public void A_result_that_does_not_follow_the_protocol_is_an_error_never_a_guess()
    {
        string request = Request("k1");
        string good = FakeAnalyzer.Result(request, "unreachable", "no-path");

        string[] bad =
        [
            "not json",
            "[]",
            Replace(good, "\"schemaVersion\":1", "\"schemaVersion\":2"),
            Replace(good, "\"name\":\"deprisk-reach\"", "\"name\":\"something-else\""),
            Replace(good, "\"language\":\"csharp\"", "\"language\":\"java\""),
            Replace(good, new string('a', 64), "not-a-digest"),
            Replace(good, "\"label\":\"unreachable\"", "\"label\":\"safe\""),
            Replace(good, "\"reason\":\"no-path\"", "\"reason\":\"because\""),
            Replace(good, "\"key\":\"k1\"", "\"key\":\"other\""),
            Replace(good, "\"results\":[", "\"results\":[{\"key\":\"k1\",\"label\":\"unknown\",\"reason\":\"no-path\",\"path\":[],\"symbol\":null},"),
            Replace(good, "\"files\":3", "\"files\":-1"),
            Replace(good, "\"path\":[]", "\"path\":[{\"from\":\"a\",\"to\":\"b\",\"kind\":\"magic\",\"file\":null,\"line\":null}]"),
            Replace(good, "\"results\":[", "\"results\":5,\"x\":["),
        ];

        foreach (string json in bad)
        {
            Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(json, ["k1"]));
        }
    }

    [Fact]
    public void Results_for_keys_that_were_not_asked_about_or_missing_keys_are_errors()
    {
        string request = Request("k1", "k2");
        string result = FakeAnalyzer.Result(request, "unreachable", "no-path");

        Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(result, ["k1"]));
        Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(result, ["k1", "k2", "k3"]));
    }

    [Fact]
    public void A_path_longer_than_the_protocol_allows_is_an_error()
    {
        string edge = """{"from":"a","to":"b","kind":"static","file":null,"line":null}""";
        string path = "[" + string.Join(",", Enumerable.Repeat(edge, 101)) + "]";
        string result = FakeAnalyzer.Result(Request("k1"), "reachable", "static-path", symbol: "A.B.C", path: path);

        Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(result, ["k1"]));
    }

    [Fact]
    public void Diagnostics_are_kept_with_a_limit()
    {
        string diagnostics = "[" + string.Join(",", Enumerable.Range(0, 50).Select(i => $"{{\"file\":\"f{i}.cs\",\"message\":\"m\"}}")) + "]";
        string result = Replace(FakeAnalyzer.Result(Request("k1"), "unreachable", "no-path"), "\"diagnostics\":[]", $"\"diagnostics\":{diagnostics}");

        AnalyzerOutput output = ReachProtocol.ParseResult(result, ["k1"]);

        Assert.Equal(20, output.Diagnostics.Count);
        Assert.Equal("f0.cs: m", output.Diagnostics[0]);
    }
}

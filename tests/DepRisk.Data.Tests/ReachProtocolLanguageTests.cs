using System.Text.Json;
using DepRisk.Core.Reach;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class ReachProtocolLanguageTests
{
    [Fact]
    public void The_request_names_its_language_and_defaults_to_csharp()
    {
        ReachTarget target = new("k", ["pkg::run"], true);

        using JsonDocument js = JsonDocument.Parse(ReachProtocol.BuildRequest("/src", "auto", ["src/a.js::go"], [target], SymbolLanguages.JavaScript));
        Assert.Equal("javascript", js.RootElement.GetProperty("language").GetString());
        Assert.Equal("src/a.js::go", js.RootElement.GetProperty("entrypoints").GetProperty("explicit")[0].GetString());
        Assert.Equal("pkg::run", js.RootElement.GetProperty("targets")[0].GetProperty("symbols")[0].GetString());

        using JsonDocument cs = JsonDocument.Parse(ReachProtocol.BuildRequest("/src", "auto", [], [target]));
        Assert.Equal("csharp", cs.RootElement.GetProperty("language").GetString());
    }

    private static string Result(string language) =>
        $$"""
        {"schemaVersion":1,"analyzer":{"name":"deprisk-reach","version":"1.0.0"},"language":"{{language}}","sourceDigest":"{{new string('a', 64)}}",
         "stats":{"files":1,"filesSkipped":0,"filesWithErrors":0,"types":0,"methods":2,"edges":1,"entrypoints":1,"reflectionSites":0},
         "entrypoints":[{"method":"src/a.js::<module>","kind":"module"}],
         "results":[{"key":"k","label":"reachable","reason":"static-path","symbol":"pkg::run","path":[{"from":"src/a.js::<module>","to":"pkg::run","kind":"static","file":"src/a.js","line":3}]}],
         "diagnostics":[{"file":"src/b.js","message":"import '@/x' not followed: may be a path alias"}]}
        """;

    [Fact]
    public void A_javascript_result_is_parsed_when_javascript_is_expected()
    {
        AnalyzerOutput output = ReachProtocol.ParseResult(Result("javascript"), ["k"], SymbolLanguages.JavaScript);

        Assert.Equal("reachable", output.Verdicts["k"].Label);
        Assert.Equal("pkg::run", output.Verdicts["k"].Symbol);
        Assert.Equal("src/b.js: import '@/x' not followed: may be a path alias", Assert.Single(output.Diagnostics));
    }

    [Fact]
    public void A_result_in_the_wrong_language_is_refused()
    {
        AnalyzerException toCsharp = Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(Result("javascript"), ["k"]));
        Assert.Contains("not the C# reachability analyzer", toCsharp.Message);

        AnalyzerException toJs = Assert.Throws<AnalyzerException>(() => ReachProtocol.ParseResult(Result("csharp"), ["k"], SymbolLanguages.JavaScript));
        Assert.Contains("not the JavaScript and TypeScript reachability analyzer", toJs.Message);
    }
}

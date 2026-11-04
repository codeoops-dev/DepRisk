using System.Text.Json;
using DepRisk.Data.Reach;

namespace DepRisk.Data.Tests;

/// <summary>A stand-in for the analyzer process: answers with a canned result built from the request it receives.</summary>
internal sealed class FakeAnalyzer : IAnalyzerProcess
{
    private readonly Func<string, string, string>? _respond;

    public FakeAnalyzer(Func<string, string, string>? respond = null) => _respond = respond;

    public string? LastRequest { get; private set; }

    public string? LastExecutable { get; private set; }

    public int Calls { get; private set; }

    public int ExitCode { get; init; }

    public string StdErr { get; init; } = string.Empty;

    public AnalyzerRun Run(string executable, string requestJson, TimeSpan timeout)
    {
        Calls++;
        LastRequest = requestJson;
        LastExecutable = executable;
        return new AnalyzerRun(ExitCode, _respond is null ? Result(requestJson, "unreachable", "no-path") : _respond(executable, requestJson), StdErr);
    }

    /// <summary>A protocol-conforming result giving every requested key the same verdict.</summary>
    public static string Result(string requestJson, string label, string reason, string? symbol = null, string path = "[]", int filesWithErrors = 0)
    {
        using JsonDocument request = JsonDocument.Parse(requestJson);
        IEnumerable<string> keys = request.RootElement.GetProperty("targets").EnumerateArray().Select(t => t.GetProperty("key").GetString()!);
        string results = string.Join(",", keys.Select(k => $"{{\"key\":{JsonSerializer.Serialize(k)},\"label\":\"{label}\",\"reason\":\"{reason}\",\"path\":{path},\"symbol\":{(symbol is null ? "null" : JsonSerializer.Serialize(symbol))}}}"));

        return $$"""
        {"schemaVersion":1,"analyzer":{"name":"deprisk-reach","version":"9.9.9"},"language":"csharp","sourceDigest":"{{new string('a', 64)}}",
         "stats":{"files":3,"filesSkipped":0,"filesWithErrors":{{filesWithErrors}},"types":2,"methods":5,"edges":4,"entrypoints":1,"reflectionSites":0},
         "entrypoints":[],"results":[{{results}}],"diagnostics":[]}
        """;
    }
}

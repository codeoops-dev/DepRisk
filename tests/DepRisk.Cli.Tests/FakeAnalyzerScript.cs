namespace DepRisk.Cli.Tests;

/// <summary>
/// A stand-in for the reachability analyzer: a small script that ignores the request and prints a canned result. (The real analyzer is
/// exercised by its own tests and by the reach-e2e job in CI.) Works on Windows (.cmd) and on Unix (sh).
/// </summary>
internal static class FakeAnalyzerScript
{
    /// <summary>A protocol-conforming result for the keys of the reach fixtures: 0001 is reachable, 0002 is unreachable.</summary>
    public const string Canned = """
        {"schemaVersion":1,"analyzer":{"name":"deprisk-reach","version":"9.9.9"},"language":"csharp","sourceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "stats":{"files":3,"filesSkipped":0,"filesWithErrors":0,"types":2,"methods":5,"edges":4,"entrypoints":1,"reflectionSites":0},
         "entrypoints":[],"results":[
           {"key":"DEPRISK-EXAMPLE-0001|Newtonsoft.Json","label":"reachable","reason":"static-path","symbol":"Newtonsoft.Json.JsonConvert.DeserializeObject",
            "path":[{"from":"Sample.Program.Main","to":"Sample.Program.Load","kind":"static","file":"Program.cs","line":9},
                    {"from":"Sample.Program.Load","to":"Newtonsoft.Json.JsonConvert.DeserializeObject","kind":"static","file":"Program.cs","line":14}]},
           {"key":"DEPRISK-EXAMPLE-0002|Example.Lib","label":"unreachable","reason":"no-path","symbol":null,"path":[]}
         ],"diagnostics":[]}
        """;

    public static string Create(string directory, string json = Canned, int exitCode = 0)
    {
        string canned = Path.Combine(directory, "canned.json");
        File.WriteAllText(canned, json);

        if (OperatingSystem.IsWindows())
        {
            string cmd = Path.Combine(directory, "fake-analyzer.cmd");
            File.WriteAllText(cmd, $"@echo off\r\ntype \"{canned}\"\r\nexit /b {exitCode}\r\n");
            return cmd;
        }

        string script = Path.Combine(directory, "fake-analyzer.sh");
        File.WriteAllText(script, $"#!/bin/sh\ncat \"{canned}\"\nexit {exitCode}\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return script;
    }
}

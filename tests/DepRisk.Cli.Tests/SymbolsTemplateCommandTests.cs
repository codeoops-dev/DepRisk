using System.Text;
using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// <c>deprisk symbols template</c> (ADR 0024) on the npm fixture (tests/fixtures/reach-npm) and, for the partial-coverage case, on the C#
/// fixture (tests/fixtures/reach). No analyzer is involved.
/// </summary>
public sealed class SymbolsTemplateCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-symtemplate-cli-" + Guid.NewGuid().ToString("N"));

    private string Osv => Path.Combine(_root, "osv");

    private string Symbols => Path.Combine(_root, "symbols");

    public SymbolsTemplateCommandTests()
    {
        Directory.CreateDirectory(_root);

        foreach (string name in new[]
        {
            "package.json",
            "package-lock.json",
            "osv/DEPRISK-NPM-0001.json",
            "osv/DEPRISK-NPM-0002.json",
            "osv/DEPRISK-NPM-0003.json",
            "osv/DEPRISK-NPM-0004.json",
            "src/app.js",
        })
        {
            // The lockfile is stored as package-lock.fixture.json: a file called package-lock.json in the repository would make a scan of
            // the repository root find both ecosystems.
            string target = Path.Combine(_root, name.Replace('/', Path.DirectorySeparatorChar));
            string resource = name == "package-lock.json" ? "package-lock.fixture.json" : name;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllText(target, NpmFixtures.ReadReachNpm(resource), new UTF8Encoding(false));
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private string[] Template(params string[] extra) => ["symbols", "template", _root, "--advisories", Osv, .. extra];

    private void WriteFixtureMap()
    {
        Directory.CreateDirectory(Symbols);
        File.WriteAllText(Path.Combine(Symbols, "npm-example.json"), NpmFixtures.ReadReachNpm("symbols/npm-example.json"));
    }

    [Fact]
    public void The_table_lists_every_pair_to_write_with_what_helps_to_write_it()
    {
        (int code, string output, string error) = Run(Template());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("deprisk symbols template: 4 to write, 0 covered, 0 not writable; ecosystem npm, language javascript", output);
        Assert.Contains("symbol maps: none given", output);
        Assert.Contains("TODO                 DEPRISK-NPM-0001 (CVE-2099-1001)  example-lib 1.0.0 (direct)", output);
        Assert.Contains("fixed in: 1.2.0", output);
        Assert.Contains("@scope/client 3.0.0 (direct)", output);
        Assert.Contains("symbols [], complete null and source \"\" on purpose", output);
        Assert.Contains("none are proposed", output);

        // deep-lib is only a dependency of a dependency: a complete list could never make it unreachable, and the table says so.
        Assert.Contains("deep-lib 1.0.0 (transitive)", output);
        Assert.Contains("transitive only: even a complete list cannot make this unreachable", output);
    }

    [Fact]
    public void The_json_is_the_draft_and_is_the_same_every_time()
    {
        (int code, string first, _) = Run(Template("--format", "json"));
        (_, string second, _) = Run(Template("--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(first, second);

        using JsonDocument document = JsonDocument.Parse(first);
        Assert.Equal("javascript", document.RootElement.GetProperty("language").GetString());

        JsonElement[] entries = document.RootElement.GetProperty("entries").EnumerateArray().ToArray();
        Assert.Equal(new[] { "DEPRISK-NPM-0001", "DEPRISK-NPM-0002", "DEPRISK-NPM-0003", "DEPRISK-NPM-0004" }, entries.Select(e => e.GetProperty("advisory").GetString()).ToArray());
        Assert.Equal(new[] { "example-lib", "other-lib", "deep-lib", "@scope/client" }, entries.Select(e => e.GetProperty("package").GetString()).ToArray());
        Assert.All(entries, e =>
        {
            Assert.Equal(0, e.GetProperty("symbols").GetArrayLength());
            Assert.Equal(JsonValueKind.Null, e.GetProperty("complete").ValueKind);
            Assert.Equal(string.Empty, e.GetProperty("source").GetString());
        });
    }

    [Fact]
    public void Out_writes_the_draft_and_the_table_still_prints()
    {
        string file = Path.Combine(_root, "draft.json");

        (int code, string output, _) = Run(Template("--out", file));
        (_, string json, _) = Run(Template("--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Wrote a draft with 4 entries to", output);
        Assert.Contains("TODO", output);
        Assert.Equal(json, File.ReadAllText(file));
        Assert.False(File.ReadAllText(file).Contains('\r'));
    }

    [Fact]
    public void Json_with_out_writes_the_file_and_prints_only_a_note()
    {
        string file = Path.Combine(_root, "draft.json");

        (int code, string output, _) = Run(Template("--format", "json", "--out", file));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.StartsWith("Wrote a draft with 4 entries", output);
        Assert.True(File.Exists(file));
        Assert.False(output.Contains("schemaVersion"));
    }

    [Fact]
    public void A_file_that_exists_is_never_replaced_without_force()
    {
        string file = Path.Combine(_root, "draft.json");
        File.WriteAllText(file, "my filled-in work");

        (int code, _, string error) = Run(Template("--out", file));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("already exists", error);
        Assert.Contains("--force", error);
        Assert.Equal("my filled-in work", File.ReadAllText(file));

        (int forced, _, _) = Run(Template("--out", file, "--force"));

        Assert.Equal((int)ExitCode.Success, forced);
        Assert.Contains("\"entries\"", File.ReadAllText(file));
    }

    [Fact]
    public void Force_without_out_is_an_input_error()
    {
        (int code, _, string error) = Run(Template("--force"));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("--force only applies together with --out", error);
    }

    [Fact]
    public void Pairs_that_an_existing_map_covers_are_left_out_and_nothing_is_written_when_nothing_is_missing()
    {
        WriteFixtureMap();
        string file = Path.Combine(_root, "draft.json");

        (int code, string output, _) = Run(Template("--symbols", Symbols, "--out", file));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("0 to write, 4 covered, 0 not writable", output);
        Assert.Contains("covered (incomplete) DEPRISK-NPM-0004", output);
        Assert.Contains("Nothing to write", output);
        Assert.False(File.Exists(file));
        Assert.False(output.Contains("symbols [], complete null"));
    }

    [Fact]
    public void An_existing_map_leaves_out_only_what_it_covers()
    {
        Directory.CreateDirectory(Symbols);
        File.WriteAllText(
            Path.Combine(Symbols, "one.json"),
            """
            {"schemaVersion":1,"language":"javascript","entries":[
              {"advisory":"CVE-2099-1001","package":"example-lib","symbols":["parse"],"complete":true,"source":"test"}]}
            """);

        (int code, string json, _) = Run(Template("--symbols", Symbols, "--format", "json"));

        Assert.Equal((int)ExitCode.Success, code);
        using JsonDocument document = JsonDocument.Parse(json);
        string[] advisories = document.RootElement.GetProperty("entries").EnumerateArray().Select(e => e.GetProperty("advisory").GetString()!).ToArray();
        Assert.Equal(new[] { "DEPRISK-NPM-0002", "DEPRISK-NPM-0003", "DEPRISK-NPM-0004" }, advisories);
    }

    [Fact]
    public void A_map_for_the_other_language_covers_nothing()
    {
        Directory.CreateDirectory(Symbols);
        File.WriteAllText(
            Path.Combine(Symbols, "cs.json"),
            """
            {"schemaVersion":1,"language":"csharp","entries":[
              {"advisory":"DEPRISK-NPM-0001","package":"example-lib","symbols":["Example.Lib.Thing.Run"],"complete":true,"source":"test"}]}
            """);

        (_, string output, _) = Run(Template("--symbols", Symbols));

        Assert.Contains("4 to write, 0 covered", output);
    }

    [Fact]
    public void A_draft_left_in_the_symbols_directory_makes_reach_fail_instead_of_reading_it_as_no_symbols()
    {
        Directory.CreateDirectory(Symbols);
        (int code, _, _) = Run(Template("--format", "json", "--out", Path.Combine(Symbols, "draft.json")));
        Assert.Equal((int)ExitCode.Success, code);

        (int reach, string output, string error) = Run("reach", _root, "--advisories", Osv, "--symbols", Symbols, "--analyzer", Path.Combine(_root, "no-such-analyzer"));

        Assert.Equal((int)ExitCode.InvalidInput, reach);
        Assert.Equal(string.Empty, output);
        Assert.Contains("draft.json", error);
        Assert.Contains("entry 0", error);
    }

    [Fact]
    public void Text_from_the_advisory_cannot_reach_the_terminal_as_control_characters()
    {
        File.WriteAllText(
            Path.Combine(Osv, "DEPRISK-NPM-EVIL.json"),
            """
            {"id":"DEPRISK-NPM-EVIL","aliases":["CVE-2099-6666"],"summary":"harmless\u001b[31m red \u0007 text",
             "affected":[{"package":{"ecosystem":"npm","name":"example-lib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}
            """);

        (int code, string output, _) = Run(Template());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("DEPRISK-NPM-EVIL", output);
        Assert.False(output.Contains('\u001b'));
        Assert.False(output.Contains('\u0007'));
    }

    [Fact]
    public void An_advisory_id_a_map_cannot_hold_is_reported_and_not_drafted()
    {
        File.WriteAllText(
            Path.Combine(Osv, "BAD.json"),
            """
            {"id":"BAD ID 1","summary":"id with a space",
             "affected":[{"package":{"ecosystem":"npm","name":"example-lib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}
            """);

        (int code, string output, _) = Run(Template());

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("4 to write, 0 covered, 1 not writable", output);
        Assert.Contains("NOT WRITABLE", output);
        Assert.Contains("no entry can be drafted for it", output);

        (_, string json, _) = Run(Template("--format", "json"));
        Assert.False(json.Contains("BAD ID 1"));
    }

    [Fact]
    public void The_csharp_fixture_leaves_out_what_its_map_covers()
    {
        string project = Path.Combine(_root, "cs", "proj");
        Directory.CreateDirectory(project);
        File.WriteAllText(Path.Combine(project, "project.assets.json"), NpmFixtures.ReadReach("assets/project.assets.json"));
        string osv = Path.Combine(_root, "cs", "osv");
        Directory.CreateDirectory(osv);

        foreach (string id in new[] { "0001", "0002", "0003" })
        {
            File.WriteAllText(Path.Combine(osv, $"DEPRISK-EXAMPLE-{id}.json"), NpmFixtures.ReadReach($"osv/DEPRISK-EXAMPLE-{id}.json"));
        }

        string map = Path.Combine(_root, "cs", "example.json");
        File.WriteAllText(map, NpmFixtures.ReadReach("symbols/example.json"));

        (int code, string output, _) = Run("symbols", "template", project, "--advisories", osv, "--symbols", map);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("1 to write, 2 covered, 0 not writable; ecosystem NuGet, language csharp", output);
        Assert.Contains("covered (incomplete) DEPRISK-EXAMPLE-0001", output);
        Assert.Contains("TODO                 DEPRISK-EXAMPLE-0003  Other.Lib 2.0.0 (direct)", output);
        Assert.Contains("Example.Lib 1.0.0 (transitive)", output);

        (_, string json, _) = Run("symbols", "template", project, "--advisories", osv, "--symbols", map, "--format", "json");
        using JsonDocument document = JsonDocument.Parse(json);
        Assert.Equal("csharp", document.RootElement.GetProperty("language").GetString());
        Assert.Equal("DEPRISK-EXAMPLE-0003", Assert.Single(document.RootElement.GetProperty("entries").EnumerateArray()).GetProperty("advisory").GetString());
    }

    [Fact]
    public void In_an_initialized_project_the_command_is_audited_with_the_file_it_wrote()
    {
        Assert.Equal((int)ExitCode.Success, Run("init", _root).Code);
        string file = Path.Combine(_root, "draft.json");

        (int code, _, _) = Run(Template("--out", file));
        Assert.Equal((int)ExitCode.Success, code);

        string[] lines = File.ReadAllLines(Path.Combine(_root, ".deprisk", "audit.log"));
        using JsonDocument entry = JsonDocument.Parse(lines[^1]);
        Assert.Equal("symbols-template", entry.RootElement.GetProperty("command").GetString());
        Assert.Equal(file.Replace('\\', '/'), entry.RootElement.GetProperty("changes")[0].GetProperty("subject").GetString());

        (int verify, _, _) = Run("audit", "verify", _root);
        Assert.Equal((int)ExitCode.Success, verify);
    }

    [Fact]
    public void Wrong_use_is_an_input_error()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run("symbols").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("symbols", "bogus").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("symbols", "template", _root).Code);

        (int format, _, string formatError) = Run(Template("--format", "sarif"));
        Assert.Equal((int)ExitCode.InvalidInput, format);
        Assert.Contains("not supported for 'symbols template'", formatError);

        (int option, _, string optionError) = Run(Template("--bogus"));
        Assert.Equal((int)ExitCode.InvalidInput, option);
        Assert.Contains("unknown option '--bogus' for 'symbols template'", optionError);

        (int twice, _, _) = Run(Template("another-path"));
        Assert.Equal((int)ExitCode.InvalidInput, twice);
    }

    [Fact]
    public void The_command_is_in_the_usage_text()
    {
        (int code, string output, _) = Run("--help");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("symbols template [path]", output);
    }
}

using System.IO.Compression;
using System.Text;
using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class RankCommandTests : IDisposable
{
    private const string SampleAssets = """
    {
      "version": 3,
      "targets": {
        "net10.0": {
          "Pkg.One/1.0.0": { "type": "package", "dependencies": { "Pkg.Two": "2.0.0" } },
          "Pkg.Two/2.0.0": { "type": "package" },
          "Pkg.Three/3.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net10.0": ["Pkg.One >= 1.0.0", "Pkg.Three >= 3.0.0"] },
      "project": { "restore": { "projectName": "Sample" } }
    }
    """;

    private const string Critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    private const string Medium = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-rank-" + Guid.NewGuid().ToString("N"));

    public RankCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "Sample", "obj"));
        File.WriteAllText(Path.Combine(_root, "Sample", "obj", "project.assets.json"), SampleAssets);
        Directory.CreateDirectory(AdvisoryDir);

        // Three vulnerable packages: the highest CVSS has no exploitation signal, the lowest is in KEV.
        WriteAdvisory("a.json", Advisory("GHSA-aaa", "CVE-2025-0001", "Pkg.One", Critical, "CRITICAL", "Critical but quiet"));
        WriteAdvisory("b.json", Advisory("GHSA-bbb", "CVE-2025-0002", "Pkg.Two", Medium, "MODERATE", "Medium but exploited"));
        WriteAdvisory("c.json", Advisory("GHSA-ccc", "CVE-2025-0003", "Pkg.Three", Medium, "MODERATE", "Medium with some EPSS"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string AdvisoryDir => Path.Combine(_root, "osv");

    private string EpssPath => Path.Combine(_root, "epss.csv");

    private string KevPath => Path.Combine(_root, "kev.json");

    private string LogPath => Path.Combine(_root, ".deprisk", "audit.log");

    private static string Advisory(string id, string cve, string package, string vector, string severity, string summary) => $$"""
        {
          "id": "{{id}}",
          "aliases": ["{{cve}}"],
          "summary": {{JsonSerializer.Serialize(summary)}},
          "severity": [ { "type": "CVSS_V3", "score": "{{vector}}" } ],
          "database_specific": { "severity": "{{severity}}" },
          "affected": [ { "package": { "ecosystem": "NuGet", "name": "{{package}}" },
            "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "99.0.0" } ] } ] } ]
        }
        """;

    private void WriteAdvisory(string name, string content) => File.WriteAllText(Path.Combine(AdvisoryDir, name), content);

    private void WriteSignals()
    {
        File.WriteAllText(
            EpssPath,
            "#model_version:v2025.03.14,score_date:2026-10-20T12:55:00Z\ncve,epss,percentile\nCVE-2025-0001,0.0100,0.20\nCVE-2025-0002,0.2000,0.80\nCVE-2025-0003,0.6000,0.95\n");
        File.WriteAllText(
            KevPath,
            """{ "catalogVersion": "2026.10.20", "dateReleased": "2026-10-20T00:00:00Z", "vulnerabilities": [ { "cveID": "CVE-2025-0002", "dateAdded": "2026-01-01", "knownRansomwareCampaignUse": "Known" } ] }""");
    }

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private static string[] Ids(JsonElement root) =>
        root.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("id").GetString()!).ToArray();

    [Fact]
    public void Kev_first_then_epss_then_cvss()
    {
        WriteSignals();

        (int code, string output, string error) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;

        // bbb is in KEV; ccc has the next highest EPSS; aaa has the highest CVSS but the lowest EPSS.
        Assert.Equal(new[] { "GHSA-bbb", "GHSA-ccc", "GHSA-aaa" }, Ids(root));
        Assert.Equal(new[] { 1, 2, 3 }, root.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("rank").GetInt32()).ToArray());

        JsonElement first = root.GetProperty("findings")[0];
        Assert.Equal("CVE-2025-0002", first.GetProperty("signals").GetProperty("kev").GetProperty("cve").GetString());
        Assert.True(first.GetProperty("signals").GetProperty("kev").GetProperty("knownRansomwareUse").GetBoolean());
        Assert.Equal(0.2, first.GetProperty("signals").GetProperty("epss").GetProperty("probability").GetDouble());
        Assert.Equal(5.3, first.GetProperty("signals").GetProperty("cvss").GetProperty("baseScore").GetDouble());

        JsonElement signals = root.GetProperty("signals");
        Assert.Equal("epss.csv", signals.GetProperty("epss").GetProperty("source").GetString());
        Assert.Equal("v2025.03.14", signals.GetProperty("epss").GetProperty("version").GetString());
        Assert.Equal(3, signals.GetProperty("epss").GetProperty("entries").GetInt32());
        Assert.Equal("2026.10.20", signals.GetProperty("kev").GetProperty("version").GetString());
        Assert.Equal("baseline-kev-epss-cvss", root.GetProperty("method").GetString());
    }

    [Fact]
    public void Without_signal_files_cvss_orders_and_the_output_says_the_signals_are_missing()
    {
        (int code, string output, _) = Run("rank", _root, "--advisories", AdvisoryDir);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("EPSS: not supplied", output);
        Assert.Contains("KEV: not supplied", output);
        Assert.Contains("findings: 3", output);

        int critical = output.IndexOf("GHSA-aaa", StringComparison.Ordinal);
        int moderate = output.IndexOf("GHSA-bbb", StringComparison.Ordinal);
        Assert.True(critical >= 0 && critical < moderate, "the critical finding must come first without other signals");
    }

    [Fact]
    public void The_table_shows_rank_signals_and_the_method()
    {
        WriteSignals();

        (_, string output, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath);

        Assert.Contains("KEV+ransomware", output);
        Assert.Contains("EPSS 0.200", output);
        Assert.Contains("CVSS 5.3 MEDIUM", output);
        Assert.Contains("CVSS 9.8 CRITICAL", output);
        Assert.Contains("model v2025.03.14", output);
        Assert.Contains("catalog 2026.10.20", output);
        Assert.Contains("baseline: in CISA KEV first", output);
        Assert.Contains("No reachability and no uncertainty yet", output);
        Assert.Contains("fixed in 99.0.0", output);
        Assert.Contains("Medium but exploited", output);
    }

    [Fact]
    public void A_gzip_epss_file_is_accepted()
    {
        WriteSignals();
        string gz = Path.Combine(_root, "epss.csv.gz");

        using (FileStream file = File.Create(gz))
        using (GZipStream zip = new(file, CompressionLevel.Optimal))
        {
            byte[] bytes = File.ReadAllBytes(EpssPath);
            zip.Write(bytes, 0, bytes.Length);
        }

        (int code, string output, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", gz, "--format", "json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("\"source\": \"epss.csv.gz\"", output);
    }

    [Fact]
    public void Output_is_identical_between_runs()
    {
        WriteSignals();

        (_, string first, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath, "--format", "json");
        (_, string second, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath, "--format", "json");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Advisory_data_is_required_and_the_message_mentions_the_optional_signal_files()
    {
        (int code, string output, string error) = Run("rank", _root);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("--advisories", error);
        Assert.Contains("--epss", error);
        Assert.Contains("--kev", error);
    }

    [Fact]
    public void Input_errors_are_exit_code_4()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, "--advisories", AdvisoryDir, "--epss", Path.Combine(_root, "missing.csv")).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, "--advisories", AdvisoryDir, "--kev", Path.Combine(_root, "missing.json")).Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, "--advisories", AdvisoryDir, "--epss").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, "--advisories", AdvisoryDir, "--format", "xml").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, "--advisories", AdvisoryDir, "--fail-on", "kev").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, "--advisories", AdvisoryDir, "--nope").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, _root, "--advisories", AdvisoryDir).Code);

        File.WriteAllText(EpssPath, "this is not an epss file");
        Assert.Equal((int)ExitCode.InvalidInput, Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath).Code);
    }

    [Fact]
    public void Malformed_signal_rows_warn_and_strict_turns_them_into_errors()
    {
        File.WriteAllText(EpssPath, "cve,epss,percentile\nCVE-2025-0001,0.5,0.6\nbroken row\n");

        (int code, string output, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("WARNING: 1 EPSS row(s) were malformed", output);

        (int strictCode, string strictOutput, string strictError) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--strict");

        Assert.Equal((int)ExitCode.InvalidInput, strictCode);
        Assert.Equal(string.Empty, strictOutput);
        Assert.Contains("EPSS", strictError);
    }

    [Fact]
    public void Control_characters_in_signal_metadata_never_reach_the_terminal()
    {
        File.WriteAllText(EpssPath, "#model_version:v1\u001b[31mRED,score_date:2026\u0007\ncve,epss,percentile\nCVE-2025-0001,0.5,0.6\n");

        (_, string table, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath);

        // Ordinal checks on purpose: xunit's string overloads are culture-sensitive and ignore control characters.
        Assert.False(table.Contains('\u001b'), "no ESC in table output");
        Assert.False(table.Contains('\u0007'), "no BEL in table output");
    }

    [Fact]
    public void In_an_initialized_project_rank_is_audited_with_digests_of_all_inputs()
    {
        WriteSignals();
        Run("init");

        Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath, "--format", "json");
        File.WriteAllText(KevPath, """{ "catalogVersion": "2026.10.21", "vulnerabilities": [] }""");
        Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath, "--format", "json");

        string[] lines = File.ReadAllLines(LogPath);
        Assert.Equal(3, lines.Length);

        using JsonDocument first = JsonDocument.Parse(lines[1]);
        using JsonDocument second = JsonDocument.Parse(lines[2]);
        Assert.Equal("rank", first.RootElement.GetProperty("command").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("inputsDigest").GetString(),
            second.RootElement.GetProperty("inputsDigest").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("outputsDigest").GetString(),
            second.RootElement.GetProperty("outputsDigest").GetString());

        Assert.Equal((int)ExitCode.Success, Run("audit", "verify").Code);
    }

    [Fact]
    public void Out_writes_the_file_and_reports_the_count()
    {
        string target = Path.Combine(_root, "ranking.json");

        (int code, string output, _) = Run("rank", _root, "--advisories", AdvisoryDir, "--format", "json", "--out", target);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("3 finding(s)", output);
        Assert.Contains("\"method\": \"baseline-kev-epss-cvss\"", File.ReadAllText(target, Encoding.UTF8));
    }

    [Fact]
    public void No_findings_says_so()
    {
        foreach (string file in Directory.GetFiles(AdvisoryDir))
        {
            File.Delete(file);
        }

        (int code, string output, _) = Run("rank", _root, "--advisories", AdvisoryDir);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("No known vulnerabilities found", output);
    }

    [Fact]
    public void Sarif_output_is_available_for_rank()
    {
        WriteSignals();

        (int code, string output, string error) = Run("rank", _root, "--advisories", AdvisoryDir, "--epss", EpssPath, "--kev", KevPath, "--format", "sarif");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);

        using JsonDocument document = JsonDocument.Parse(output);
        Assert.Equal("2.1.0", document.RootElement.GetProperty("version").GetString());

        JsonElement results = document.RootElement.GetProperty("runs")[0].GetProperty("results");
        Assert.Equal(new[] { "GHSA-bbb", "GHSA-ccc", "GHSA-aaa" }, results.EnumerateArray().Select(r => r.GetProperty("ruleId").GetString()).ToArray());
        Assert.Equal("error", results[0].GetProperty("level").GetString());
    }
}

using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

public sealed class InitAndAuditCommandTests : IDisposable
{
    private const string SampleAssets = """
    {
      "version": 3,
      "targets": { "net10.0": { "Pkg.One/1.0.0": { "type": "package" } } },
      "projectFileDependencyGroups": { "net10.0": ["Pkg.One >= 1.0.0"] },
      "project": { "restore": { "projectName": "Sample" } }
    }
    """;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-cli-" + Guid.NewGuid().ToString("N"));

    public InitAndAuditCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "Sample", "obj"));
        File.WriteAllText(Path.Combine(_root, "Sample", "obj", "project.assets.json"), SampleAssets);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string LogPath => Path.Combine(_root, ".deprisk", "audit.log");

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private string[] Lines() => File.ReadAllLines(LogPath);

    [Fact]
    public void Init_creates_the_store_and_writes_the_first_entry()
    {
        (int code, string output, string error) = Run("init");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("Initialized", output);
        Assert.True(File.Exists(Path.Combine(_root, ".deprisk", "audit.key")));
        Assert.True(File.Exists(Path.Combine(_root, ".deprisk", "audit.pub")));

        string line = Assert.Single(Lines());
        using JsonDocument entry = JsonDocument.Parse(line);
        Assert.Equal("init", entry.RootElement.GetProperty("command").GetString());
        Assert.Equal(1, entry.RootElement.GetProperty("seq").GetInt32());
        Assert.Equal("tester", entry.RootElement.GetProperty("actor").GetString());
        Assert.Equal("test-host", entry.RootElement.GetProperty("host").GetString());
        Assert.Equal("2026-10-27T12:00:00.000Z", entry.RootElement.GetProperty("timestamp").GetString());
    }

    [Fact]
    public void The_log_never_contains_the_private_key()
    {
        Run("init");
        Run("scan", _root);

        string log = File.ReadAllText(LogPath);
        string privateKey = File.ReadAllText(Path.Combine(_root, ".deprisk", "audit.key"));

        Assert.DoesNotContain("PRIVATE KEY", log);
        Assert.DoesNotContain(privateKey.Split('\n')[1], log);
    }

    [Fact]
    public void Init_a_second_time_changes_nothing()
    {
        Run("init");
        string keyBefore = File.ReadAllText(Path.Combine(_root, ".deprisk", "audit.key"));

        (int code, string output, _) = Run("init");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Already initialized", output);
        Assert.Single(Lines());
        Assert.Equal(keyBefore, File.ReadAllText(Path.Combine(_root, ".deprisk", "audit.key")));
    }

    [Fact]
    public void Init_rejects_options_and_extra_paths_and_missing_directories()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run("init", "--force").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("init", "a", "b").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("init", "no-such-dir").Code);
        Assert.False(Directory.Exists(Path.Combine(_root, ".deprisk")));
    }

    [Fact]
    public void Scan_without_init_writes_no_audit_data()
    {
        (int code, _, _) = Run("scan", _root);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.False(Directory.Exists(Path.Combine(_root, ".deprisk")));
    }

    [Fact]
    public void Scan_after_init_adds_an_entry_with_digests_and_the_redacted_arguments()
    {
        Run("init");

        (int code, _, _) = Run("scan", _root, "--format", "json", "--out", "result.json");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(2, Lines().Length);

        using JsonDocument entry = JsonDocument.Parse(Lines()[1]);
        JsonElement root = entry.RootElement;

        Assert.Equal("scan", root.GetProperty("command").GetString());
        Assert.Equal(2, root.GetProperty("seq").GetInt32());
        Assert.True(Digest.IsSha256Hex(root.GetProperty("inputsDigest").GetString()));
        Assert.True(Digest.IsSha256Hex(root.GetProperty("outputsDigest").GetString()));
        Assert.Equal(5, root.GetProperty("args").GetArrayLength());

        JsonElement change = root.GetProperty("changes")[0];
        Assert.Equal("result.json", change.GetProperty("subject").GetString());
        Assert.Equal(JsonValueKind.Null, change.GetProperty("from").ValueKind);
        Assert.Equal("written", change.GetProperty("to").GetString());
    }

    [Fact]
    public void The_scan_output_is_the_same_with_and_without_auditing()
    {
        (_, string before, _) = Run("scan", _root, "--format", "json");
        Run("init");
        (_, string after, _) = Run("scan", _root, "--format", "json");

        Assert.Equal(before, after);
    }

    [Fact]
    public void The_same_scan_gives_the_same_digests_each_time()
    {
        Run("init");
        Run("scan", _root, "--format", "json");
        Run("scan", _root, "--format", "json");

        using JsonDocument first = JsonDocument.Parse(Lines()[1]);
        using JsonDocument second = JsonDocument.Parse(Lines()[2]);

        Assert.Equal(
            first.RootElement.GetProperty("inputsDigest").GetString(),
            second.RootElement.GetProperty("inputsDigest").GetString());
        Assert.Equal(
            first.RootElement.GetProperty("outputsDigest").GetString(),
            second.RootElement.GetProperty("outputsDigest").GetString());
    }

    [Fact]
    public void A_changed_input_file_changes_the_inputs_digest()
    {
        Run("init");
        Run("scan", _root);
        File.WriteAllText(
            Path.Combine(_root, "Sample", "obj", "project.assets.json"),
            SampleAssets.Replace("Pkg.One/1.0.0", "Pkg.One/1.0.1", StringComparison.Ordinal).Replace(">= 1.0.0", ">= 1.0.1", StringComparison.Ordinal));
        Run("scan", _root);

        using JsonDocument first = JsonDocument.Parse(Lines()[1]);
        using JsonDocument second = JsonDocument.Parse(Lines()[2]);

        Assert.NotEqual(
            first.RootElement.GetProperty("inputsDigest").GetString(),
            second.RootElement.GetProperty("inputsDigest").GetString());
    }

    [Fact]
    public void Verify_accepts_an_untouched_log_and_prints_the_head()
    {
        Run("init");
        Run("scan", _root);

        (int code, string output, string error) = Run("audit", "verify");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("Audit log OK: 2 entries", output);
        Assert.Contains("head: " + Digest.Sha256Hex(Lines()[1]), output);
    }

    [Fact]
    public void Verify_reports_a_tampered_log_with_exit_code_3_and_the_line()
    {
        Run("init");
        Run("scan", _root);
        string[] lines = Lines();
        lines[1] = lines[1].Replace("\"actor\":\"tester\"", "\"actor\":\"mallory\"", StringComparison.Ordinal);
        File.WriteAllText(LogPath, string.Concat(lines.Select(l => l + "\n")));

        (int code, string output, string error) = Run("audit", "verify");

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("FAILED at line 2", error);
    }

    [Fact]
    public void Verify_with_a_pinned_head_catches_truncation()
    {
        Run("init");
        Run("scan", _root);
        (_, string output, _) = Run("audit", "verify");
        string head = output.Split('\n').Single(l => l.StartsWith("head: ", StringComparison.Ordinal))["head: ".Length..];

        File.WriteAllText(LogPath, Lines()[0] + "\n");

        Assert.Equal((int)ExitCode.Success, Run("audit", "verify").Code);
        Assert.Equal((int)ExitCode.AuditIntegrityFailure, Run("audit", "verify", "--head", head).Code);
    }

    [Fact]
    public void Verify_can_use_a_public_key_supplied_from_outside()
    {
        Run("init");
        Run("scan", _root);
        string copy = Path.Combine(_root, "auditor.pub");
        File.Copy(Path.Combine(_root, ".deprisk", "audit.pub"), copy);

        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", "--pubkey", copy).Code);

        // Someone replaces the public key next to the log with their own: verification against the real key now fails.
        using DepRisk.Audit.AuditSigner other = DepRisk.Audit.AuditSigner.Generate();
        string otherPath = Path.Combine(_root, "other.pub");
        File.WriteAllText(otherPath, other.ExportPublicPem());

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, Run("audit", "verify", "--pubkey", otherPath).Code);
    }

    [Fact]
    public void Verify_input_errors()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run("audit", "verify").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("audit").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("audit", "explode").Code);

        Run("init");
        Assert.Equal((int)ExitCode.InvalidInput, Run("audit", "verify", "--head", "nothex").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("audit", "verify", "--pubkey").Code);
        Assert.Equal((int)ExitCode.InvalidInput, Run("audit", "verify", "--nope").Code);
    }

    [Fact]
    public void Scan_stops_with_exit_code_3_when_the_signing_key_is_missing()
    {
        Run("init");
        File.Delete(Path.Combine(_root, ".deprisk", "audit.key"));

        (int code, string output, string error) = Run("scan", _root);

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("signing key is missing", error);
    }

    [Fact]
    public void Scan_stops_with_exit_code_3_when_the_log_is_damaged_instead_of_extending_it()
    {
        Run("init");
        File.AppendAllText(LogPath, "{\"half\":");

        (int code, _, _) = Run("scan", _root);

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
    }

    [Fact]
    public void Doctor_reports_the_audit_store_state()
    {
        (_, string before, _) = Run("doctor");
        Run("init");
        (_, string after, _) = Run("doctor");

        Assert.Contains("not initialized", before);
        Assert.Contains("initialized:", after);
    }
}

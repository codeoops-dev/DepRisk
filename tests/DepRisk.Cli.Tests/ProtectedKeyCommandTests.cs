using System.Text.Json;
using DepRisk.Audit;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>A passphrase for the audit key, a key outside .deprisk, and doctor --format json (S26, ADR 0030).</summary>
public sealed class ProtectedKeyCommandTests : IDisposable
{
    private const string Secret = "correct horse battery staple";

    private const string SampleAssets = """
        { "version": 3,
          "targets": { "net10.0": { "Pkg.One/1.0.0": { "type": "package" } } },
          "projectFileDependencyGroups": { "net10.0": ["Pkg.One >= 1.0.0"] },
          "project": { "restore": { "projectName": "Sample" } } }
        """;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-protected-key-" + Guid.NewGuid().ToString("N"));

    public ProtectedKeyCommandTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "Sample", "obj"));
        File.WriteAllText(Path.Combine(_root, "Sample", "obj", "project.assets.json"), SampleAssets);
        Directory.CreateDirectory(Path.Combine(_root, "secure"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string KeyPath => Path.Combine(_root, ".deprisk", "audit.key");

    private string LogPath => Path.Combine(_root, ".deprisk", "audit.log");

    private (int Code, string Out, string Err) Run(IReadOnlyDictionary<string, string> environment, params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root, environment));
        return (code, output.ToString(), error.ToString());
    }

    private (int Code, string Out, string Err) Run(params string[] args) => Run(new Dictionary<string, string>(), args);

    private static Dictionary<string, string> Passphrase(string value = Secret) => new() { [KeyPassphrase.EnvironmentVariable] = value };

    // ---- --encrypt ----

    [Fact]
    public void Init_encrypt_without_a_passphrase_is_an_input_error_that_says_where_to_give_one()
    {
        (int code, _, string error) = Run("init", "--encrypt");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("DEPRISK_KEY_PASSPHRASE", error);
        Assert.Contains("not taken from the command line", error);
        Assert.False(Directory.Exists(Path.Combine(_root, ".deprisk")));
    }

    [Fact]
    public void Init_encrypt_writes_an_encrypted_key_and_later_commands_sign_with_the_passphrase_and_verify()
    {
        (int code, string output, string error) = Run(Passphrase(), "init", "--encrypt");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("encrypted with your passphrase", output);
        Assert.DoesNotContain(Secret, output);
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", File.ReadAllText(KeyPath));

        (int scanCode, _, string scanError) = Run(Passphrase(), "scan", _root);
        Assert.True(scanCode == (int)ExitCode.Success, scanError);

        (int verifyCode, string verify, _) = Run("audit", "verify", _root);
        Assert.Equal((int)ExitCode.Success, verifyCode);
        Assert.Contains("2 entries", verify);

        string log = File.ReadAllText(LogPath);
        Assert.DoesNotContain(Secret, log);
        Assert.DoesNotContain("PRIVATE KEY", log);
        Assert.Contains("created, encrypted with a passphrase", log);
        Assert.DoesNotContain(Secret, File.ReadAllText(Path.Combine(_root, ".deprisk", "audit.pub")));
    }

    [Fact]
    public void The_passphrase_can_come_from_a_file()
    {
        string file = Path.Combine(_root, "secure", "pass.txt");
        File.WriteAllText(file, Secret + "\n");
        Dictionary<string, string> fromFile = new() { [KeyPassphrase.FileEnvironmentVariable] = file };

        Assert.Equal((int)ExitCode.Success, Run(fromFile, "init", "--encrypt").Code);
        Assert.Equal((int)ExitCode.Success, Run(fromFile, "scan", _root).Code);
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);
    }

    [Fact]
    public void A_passphrase_that_is_too_short_or_contradictory_is_an_input_error_and_nothing_is_created()
    {
        Assert.Equal((int)ExitCode.InvalidInput, Run(Passphrase("short"), "init", "--encrypt").Code);

        Dictionary<string, string> both = Passphrase();
        both[KeyPassphrase.FileEnvironmentVariable] = "/nowhere";
        (int code, _, string error) = Run(both, "init", "--encrypt");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("use one", error);
        Assert.False(AuditStore.IsInitialized(_root));
    }

    [Fact]
    public void A_command_in_a_project_with_an_encrypted_key_stops_when_the_passphrase_is_missing_or_wrong()
    {
        Assert.Equal((int)ExitCode.Success, Run(Passphrase(), "init", "--encrypt").Code);

        (int missingCode, _, string missing) = Run("scan", _root);
        Assert.Equal((int)ExitCode.AuditIntegrityFailure, missingCode);
        Assert.Contains("is encrypted", missing);
        Assert.Contains("DEPRISK_KEY_PASSPHRASE", missing);

        (int wrongCode, _, string wrong) = Run(Passphrase("not the passphrase"), "scan", _root);
        Assert.Equal((int)ExitCode.AuditIntegrityFailure, wrongCode);
        Assert.Contains("passphrase is wrong or the file is damaged", wrong);
        Assert.DoesNotContain("not the passphrase", wrong);
        Assert.DoesNotContain(Secret, wrong);

        // Neither command added an entry.
        Assert.Single(File.ReadAllLines(LogPath));
    }

    // ---- --key-file ----

    [Fact]
    public void Init_key_file_puts_the_key_elsewhere_and_commands_find_it_through_the_variable()
    {
        string keyFile = Path.Combine(_root, "secure", "audit.key");

        (int code, string output, string error) = Run("init", "--key-file", keyFile);

        Assert.True(code == (int)ExitCode.Success, error);
        Assert.True(File.Exists(keyFile));
        Assert.False(File.Exists(KeyPath));
        Assert.Contains(keyFile, output);
        Assert.Contains("DEPRISK_KEY_FILE", output);

        // The path of the key is not written to the log, and the first entry says only that the key is outside.
        string log = File.ReadAllText(LogPath);
        Assert.DoesNotContain(keyFile, log);
        Assert.DoesNotContain("secure", log);
        Assert.Contains("private key file outside .deprisk", log);
        Assert.Contains("\"***\"", log);

        (int withoutCode, _, string without) = Run("scan", _root);
        Assert.Equal((int)ExitCode.AuditIntegrityFailure, withoutCode);
        Assert.Contains("the signing key is missing", without);

        Dictionary<string, string> found = new() { [AuditStore.KeyFileEnvironmentVariable] = keyFile };
        Assert.Equal((int)ExitCode.Success, Run(found, "scan", _root).Code);
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);
    }

    [Fact]
    public void Key_file_and_encrypt_work_together_and_a_relative_key_file_is_taken_from_the_working_directory()
    {
        (int code, string error) = (Run(Passphrase(), "init", "--encrypt", "--key-file", "secure/audit.key").Code, string.Empty);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.True(AuditSigner.IsEncryptedKey(File.ReadAllText(Path.Combine(_root, "secure", "audit.key"))));

        Dictionary<string, string> environment = Passphrase();
        environment[AuditStore.KeyFileEnvironmentVariable] = "secure/audit.key";
        Assert.Equal((int)ExitCode.Success, Run(environment, "scan", _root).Code);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void A_key_file_that_cannot_be_created_is_an_input_error_and_nothing_is_overwritten()
    {
        (int noDirectory, _, string noDirectoryError) = Run("init", "--key-file", Path.Combine(_root, "nowhere", "audit.key"));
        Assert.Equal((int)ExitCode.InvalidInput, noDirectory);
        Assert.Contains("does not exist", noDirectoryError);

        string existing = Path.Combine(_root, "secure", "existing.key");
        File.WriteAllText(existing, "do not touch");
        (int existingCode, _, string existingError) = Run("init", "--key-file", existing);
        Assert.Equal((int)ExitCode.InvalidInput, existingCode);
        Assert.Contains("cannot create", existingError);
        Assert.Equal("do not touch", File.ReadAllText(existing));
        Assert.False(AuditStore.IsInitialized(_root));
    }

    [Fact]
    public void A_key_that_is_not_the_stores_is_refused_before_anything_is_written()
    {
        Assert.Equal((int)ExitCode.Success, Run("init").Code);

        using AuditSigner other = AuditSigner.Generate();
        string wrong = Path.Combine(_root, "secure", "other.key");
        File.WriteAllText(wrong, other.ExportPrivatePem());

        (int code, _, string error) = Run(new Dictionary<string, string> { [AuditStore.KeyFileEnvironmentVariable] = wrong }, "scan", _root);

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Contains("is not the key of this audit store", error);
        Assert.Single(File.ReadAllLines(LogPath));
        Assert.Equal((int)ExitCode.Success, Run("audit", "verify", _root).Code);
    }

    [Fact]
    public void The_existing_behavior_is_unchanged_for_a_plain_key()
    {
        Assert.Equal((int)ExitCode.Success, Run("init").Code);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", File.ReadAllText(KeyPath));

        // A passphrase variable that is set does not matter to a key that has none.
        Assert.Equal((int)ExitCode.Success, Run(Passphrase(), "scan", _root).Code);
        Assert.Equal((int)ExitCode.Success, Run("scan", _root).Code);
        Assert.Contains("3 entries", Run("audit", "verify", _root).Out);
    }

    // ---- vex --sign with an encrypted key ----

    [Fact]
    public void Vex_sign_takes_the_passphrase_of_an_encrypted_key_from_the_environment_only()
    {
        string project = Path.Combine(_root, "proj");
        string osv = Path.Combine(_root, "osv");
        Directory.CreateDirectory(project);
        Directory.CreateDirectory(osv);
        File.WriteAllText(Path.Combine(project, "project.assets.json"), NpmFixtures.ReadReach("assets/project.assets.json"));
        File.WriteAllText(Path.Combine(osv, "DEPRISK-EXAMPLE-0001.json"), NpmFixtures.ReadReach("osv/DEPRISK-EXAMPLE-0001.json"));

        using AuditSigner signer = AuditSigner.Generate();
        string keyFile = Path.Combine(_root, "vex.key");
        File.WriteAllText(keyFile, signer.ExportEncryptedPrivatePem(Secret));
        File.WriteAllText(Path.Combine(_root, "subject.bin"), "pretend this is a package");

        string[] args =
        [
            "vex", project, "--advisories", osv, "--product", "pkg:nuget/App@1.0.0", "--author", "tests", "--timestamp", "2026-11-11T12:00:00Z",
            "--sign", "--key", keyFile, "--subject-file", Path.Combine(_root, "subject.bin"),
        ];

        (int withoutCode, _, string without) = Run(args);
        Assert.Equal((int)ExitCode.InvalidInput, withoutCode);
        Assert.Contains("is encrypted", without);

        (int code, string envelope, string error) = Run(Passphrase(), args);
        Assert.True(code == (int)ExitCode.Success, error);
        Assert.DoesNotContain("PRIVATE KEY", envelope);
        Assert.DoesNotContain(Secret, envelope);
    }

    // ---- doctor ----

    private JsonElement Doctor(IReadOnlyDictionary<string, string> environment, out int warnings)
    {
        (int code, string output, string error) = Run(environment, "doctor", "--format", "json");

        Assert.True(code == (int)ExitCode.Success, error);
        JsonDocument document = JsonDocument.Parse(output);
        warnings = document.RootElement.GetProperty("warnings").GetInt32();
        return document.RootElement;
    }

    private static JsonElement Check(JsonElement doctor, string name) =>
        doctor.GetProperty("checks").EnumerateArray().Single(c => c.GetProperty("name").GetString() == name);

    [Fact]
    public void Doctor_json_has_the_documented_shape_and_the_warning_count_matches_the_checks()
    {
        JsonElement doctor = Doctor(new Dictionary<string, string>(), out int warnings);

        Assert.Equal(1, doctor.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("deprisk", doctor.GetProperty("tool").GetProperty("name").GetString());
        Assert.False(string.IsNullOrEmpty(doctor.GetProperty("tool").GetProperty("version").GetString()));

        string[] statuses = ["ok", "info", "warn"];

        foreach (JsonElement check in doctor.GetProperty("checks").EnumerateArray())
        {
            Assert.Equal(3, check.EnumerateObject().Count());
            Assert.False(string.IsNullOrEmpty(check.GetProperty("name").GetString()));
            Assert.Contains(check.GetProperty("status").GetString()!, statuses);
            Assert.False(string.IsNullOrEmpty(check.GetProperty("detail").GetString()));
        }

        Assert.Equal(doctor.GetProperty("checks").EnumerateArray().Count(c => c.GetProperty("status").GetString() == "warn"), warnings);
        Assert.Equal(new[] { "version", "runtime", "platform" }, doctor.GetProperty("checks").EnumerateArray().Take(3).Select(c => c.GetProperty("name").GetString()).ToArray());
        Assert.DoesNotContain(doctor.GetProperty("checks").EnumerateArray(), c => c.GetProperty("name").GetString() == "audit-key");   // no audit store here
    }

    [Fact]
    public void Doctor_describes_the_signing_key_of_a_store_and_warns_about_what_would_make_commands_stop()
    {
        // Unencrypted key: ok (the file mode is restricted by init on systems that have one).
        Assert.Equal((int)ExitCode.Success, Run("init").Code);
        JsonElement plain = Check(Doctor(new Dictionary<string, string>(), out _), "audit-key");
        Assert.Equal("ok", plain.GetProperty("status").GetString());
        Assert.Contains("not encrypted", plain.GetProperty("detail").GetString());

        // Key missing.
        string moved = Path.Combine(_root, "moved.key");
        File.Move(KeyPath, moved);
        JsonElement missing = Check(Doctor(new Dictionary<string, string>(), out int warnings), "audit-key");
        Assert.Equal("warn", missing.GetProperty("status").GetString());
        Assert.Contains("exit code 3", missing.GetProperty("detail").GetString());
        Assert.True(warnings >= 1);

        // The same key found through the variable.
        JsonElement found = Check(Doctor(new Dictionary<string, string> { [AuditStore.KeyFileEnvironmentVariable] = moved }, out _), "audit-key");
        Assert.Equal("ok", found.GetProperty("status").GetString());
    }

    [Fact]
    public void Doctor_reports_an_encrypted_key_ok_with_its_passphrase_source_and_warns_without_or_with_a_wrong_one()
    {
        Assert.Equal((int)ExitCode.Success, Run(Passphrase(), "init", "--encrypt").Code);

        JsonElement ok = Check(Doctor(Passphrase(), out _), "audit-key");
        Assert.Equal("ok", ok.GetProperty("status").GetString());
        Assert.Contains("encrypted with a passphrase", ok.GetProperty("detail").GetString());
        Assert.Contains("passphrase from DEPRISK_KEY_PASSPHRASE", ok.GetProperty("detail").GetString());
        Assert.DoesNotContain(Secret, ok.GetProperty("detail").GetString());

        JsonElement without = Check(Doctor(new Dictionary<string, string>(), out _), "audit-key");
        Assert.Equal("warn", without.GetProperty("status").GetString());
        Assert.Contains("is encrypted", without.GetProperty("detail").GetString());

        JsonElement wrong = Check(Doctor(Passphrase("not the passphrase"), out _), "audit-key");
        Assert.Equal("warn", wrong.GetProperty("status").GetString());
        Assert.DoesNotContain("not the passphrase", wrong.GetProperty("detail").GetString());
    }

    [Fact]
    public void Doctor_warns_about_an_unprotected_key_that_other_users_can_read()
    {
        if (OperatingSystem.IsWindows())
        {
            return;   // there is no such file mode to check there
        }

        Assert.Equal((int)ExitCode.Success, Run("init").Code);
        File.SetUnixFileMode(KeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        JsonElement check = Check(Doctor(new Dictionary<string, string>(), out _), "audit-key");

        Assert.Equal("warn", check.GetProperty("status").GetString());
        Assert.Contains("can be read by other users", check.GetProperty("detail").GetString());
    }

    [Fact]
    public void Doctor_table_shows_the_key_line_and_the_default_format_is_still_the_table()
    {
        Assert.Equal((int)ExitCode.Success, Run("init").Code);

        (int code, string output, _) = Run("doctor");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("audit-key", output);
        Assert.StartsWith("deprisk doctor", output);
        Assert.DoesNotContain("schemaVersion", output);
    }

    [Theory]
    [InlineData("--format", "xml")]
    [InlineData("--bogus", null)]
    [InlineData("somewhere", null)]
    public void Doctor_refuses_what_it_does_not_understand(string first, string? second)
    {
        (int code, _, string error) = Run(second is null ? ["doctor", first] : ["doctor", first, second]);

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("doctor", error);
    }
}

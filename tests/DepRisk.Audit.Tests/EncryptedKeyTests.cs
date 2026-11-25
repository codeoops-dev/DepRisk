using DepRisk.Core;
using Xunit;

namespace DepRisk.Audit.Tests;

public sealed class EncryptedKeyTests : IDisposable
{
    private const string Secret = "correct horse battery staple";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-encrypted-key-" + Guid.NewGuid().ToString("N"));

    public EncryptedKeyTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static Func<string, string?> Env(params (string Name, string Value)[] variables) =>
        name => variables.Where(v => v.Name == name).Select(v => v.Value).FirstOrDefault();

    private string Write(string name, string content)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    // ---- the signer ----

    [Fact]
    public void An_encrypted_key_is_pkcs8_encrypted_pem_and_does_not_hold_the_plain_key()
    {
        using AuditSigner signer = AuditSigner.Generate();

        string pem = signer.ExportEncryptedPrivatePem(Secret);

        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", pem);
        Assert.DoesNotContain(Secret, pem);
        Assert.True(AuditSigner.IsEncryptedKey(pem));
        Assert.False(AuditSigner.IsEncryptedKey(signer.ExportPrivatePem()));
    }

    [Fact]
    public void An_encrypted_key_loads_with_its_passphrase_and_is_the_same_key()
    {
        using AuditSigner signer = AuditSigner.Generate();
        string path = Write("audit.key", signer.ExportEncryptedPrivatePem(Secret));

        using AuditSigner loaded = AuditSigner.LoadPrivate(path, () => Secret);

        Assert.Equal(signer.KeyId(), loaded.KeyId());
        Assert.True(signer.Verify("body", loaded.Sign("body")));
    }

    [Fact]
    public void A_wrong_passphrase_is_an_error_that_does_not_repeat_either_passphrase()
    {
        using AuditSigner signer = AuditSigner.Generate();
        string path = Write("audit.key", signer.ExportEncryptedPrivatePem(Secret));

        AuditException error = Assert.Throws<AuditException>(() => AuditSigner.LoadPrivate(path, () => "not the passphrase"));

        Assert.Contains("passphrase is wrong or the file is damaged", error.Message);
        Assert.DoesNotContain("not the passphrase", error.Message);
        Assert.DoesNotContain(Secret, error.Message);
    }

    [Fact]
    public void An_encrypted_key_without_a_passphrase_says_where_to_give_one()
    {
        using AuditSigner signer = AuditSigner.Generate();
        string path = Write("audit.key", signer.ExportEncryptedPrivatePem(Secret));

        foreach (Func<string?>? provider in new Func<string?>?[] { null, () => null, () => string.Empty })
        {
            AuditException error = Assert.Throws<AuditException>(() => AuditSigner.LoadPrivate(path, provider));

            Assert.Contains("is encrypted", error.Message);
            Assert.Contains("DEPRISK_KEY_PASSPHRASE", error.Message);
            Assert.Contains("DEPRISK_KEY_PASSPHRASE_FILE", error.Message);
        }
    }

    [Fact]
    public void A_key_that_is_not_encrypted_never_asks_for_a_passphrase()
    {
        using AuditSigner signer = AuditSigner.Generate();
        string path = Write("audit.key", signer.ExportPrivatePem());

        using AuditSigner loaded = AuditSigner.LoadPrivate(path, () => throw new InvalidOperationException("asked"));

        Assert.Equal(signer.KeyId(), loaded.KeyId());
    }

    [Fact]
    public void An_empty_passphrase_cannot_encrypt()
    {
        using AuditSigner signer = AuditSigner.Generate();

        Assert.Throws<ArgumentException>(() => signer.ExportEncryptedPrivatePem(string.Empty));
    }

    // ---- the store ----

    [Fact]
    public void A_store_started_with_a_passphrase_has_an_encrypted_key_that_still_signs_and_verifies()
    {
        AuditStore store = AuditStore.Initialize(_root, out AuditSigner created, keyFile: null, passphrase: Secret);
        created.Dispose();

        string keyText = File.ReadAllText(store.PrivateKeyPath);
        Assert.True(AuditSigner.IsEncryptedKey(keyText));
        Assert.DoesNotContain(Secret, keyText);
        Assert.DoesNotContain(Secret, File.ReadAllText(store.PublicKeyPath));

        using AuditSigner signer = store.LoadSigner(Env((KeyPassphrase.EnvironmentVariable, Secret)), _root);
        AuditLog log = new(store);
        log.Append(new AuditDraft("scan", [], new string('a', 64), new string('b', 64), []), TempStore.Environment(), signer);

        using AuditSigner verifier = AuditSigner.LoadPublic(store.PublicKeyPath);
        Assert.True(AuditLog.Verify(store.LogPath, verifier).Ok);
    }

    [Fact]
    public void The_passphrase_can_come_from_a_file()
    {
        AuditStore store = AuditStore.Initialize(_root, out AuditSigner created, keyFile: null, passphrase: Secret);
        created.Dispose();
        string file = Write("pass.txt", Secret + "\n");

        using AuditSigner signer = store.LoadSigner(Env((KeyPassphrase.FileEnvironmentVariable, file)), _root);

        Assert.NotNull(signer.KeyId());
    }

    [Fact]
    public void A_passphrase_shorter_than_the_minimum_is_refused_and_nothing_is_written()
    {
        AuditException error = Assert.Throws<AuditException>(() => AuditStore.Initialize(_root, out _, keyFile: null, passphrase: "short"));

        Assert.Contains("at least 12 characters", error.Message);
        Assert.False(AuditStore.IsInitialized(_root));
        Assert.False(Directory.Exists(Path.Combine(_root, AuditStore.DirectoryName)));
    }

    [Fact]
    public void The_key_can_be_written_outside_the_directory_and_is_found_through_the_variable()
    {
        string keys = Path.Combine(_root, "secure");
        Directory.CreateDirectory(keys);
        string keyFile = Path.Combine(keys, "my.key");

        AuditStore store = AuditStore.Initialize(_root, out AuditSigner created, keyFile, passphrase: null);
        created.Dispose();

        Assert.True(File.Exists(keyFile));
        Assert.False(File.Exists(store.PrivateKeyPath));
        Assert.True(File.Exists(store.PublicKeyPath));
        Assert.True(AuditStore.IsInitialized(_root));

        // Without the variable the key is looked for in the directory, where it is not.
        AuditException missing = Assert.Throws<AuditException>(() => store.LoadSigner(Env(), _root));
        Assert.Contains(store.PrivateKeyPath, missing.Message);

        using AuditSigner signer = store.LoadSigner(Env((AuditStore.KeyFileEnvironmentVariable, keyFile)), _root);
        Assert.Equal(AuditSigner.LoadPublic(store.PublicKeyPath).KeyId(), signer.KeyId());
    }

    [Fact]
    public void A_relative_key_file_variable_is_resolved_from_the_given_directory()
    {
        string keyFile = Path.Combine(_root, "my.key");
        AuditStore store = AuditStore.Initialize(_root, out AuditSigner created, keyFile, passphrase: null);
        created.Dispose();

        using AuditSigner signer = store.LoadSigner(Env((AuditStore.KeyFileEnvironmentVariable, "my.key")), _root);

        Assert.NotNull(signer);
    }

    [Fact]
    public void A_key_file_in_a_directory_that_does_not_exist_or_that_already_exists_is_refused_and_not_overwritten()
    {
        AuditException noDirectory = Assert.Throws<AuditException>(
            () => AuditStore.Initialize(_root, out _, Path.Combine(_root, "nowhere", "my.key"), passphrase: null));
        Assert.Contains("does not exist", noDirectory.Message);

        string existing = Write("existing.key", "do not touch");
        Assert.Throws<AuditException>(() => AuditStore.Initialize(_root, out _, existing, passphrase: null));
        Assert.Equal("do not touch", File.ReadAllText(existing));
        Assert.False(AuditStore.IsInitialized(_root));
    }

    [Fact]
    public void A_key_from_the_variable_that_is_not_the_keys_of_the_store_is_refused()
    {
        AuditStore store = AuditStore.Initialize(_root, out AuditSigner created, keyFile: null, passphrase: null);
        created.Dispose();

        using AuditSigner other = AuditSigner.Generate();
        string wrong = Write("other.key", other.ExportPrivatePem());

        AuditException error = Assert.Throws<AuditException>(() => store.LoadSigner(Env((AuditStore.KeyFileEnvironmentVariable, wrong)), _root));

        Assert.Contains("is not the key of this audit store", error.Message);
    }

    [Fact]
    public void An_unencrypted_key_in_the_directory_still_loads_with_no_variable_at_all()
    {
        AuditStore store = AuditStore.Initialize(_root, out AuditSigner created, keyFile: null, passphrase: null);
        created.Dispose();

        // A passphrase variable that is wrong or contradictory does not matter to a key that has none.
        using AuditSigner plain = store.LoadSigner(Env(), _root);
        using AuditSigner ignored = store.LoadSigner(
            Env((KeyPassphrase.EnvironmentVariable, "x"), (KeyPassphrase.FileEnvironmentVariable, "/nowhere")), _root);

        Assert.Equal(plain.KeyId(), ignored.KeyId());
    }

    [Fact]
    public void The_path_of_a_key_file_is_masked_in_the_arguments_that_are_logged()
    {
        IReadOnlyList<string> redacted = ArgRedactor.Redact(["init", "--key-file", "/secure/my.key", "--encrypt"]);

        Assert.Equal(["init", "--key-file", "***", "--encrypt"], redacted);
        Assert.Equal(["init", "--key-file=***"], ArgRedactor.Redact(["init", "--key-file=/secure/my.key"]));
    }
}

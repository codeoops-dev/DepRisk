using Xunit;

namespace DepRisk.Audit.Tests;

public sealed class AuditStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-store-" + Guid.NewGuid().ToString("N"));

    public AuditStoreTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void Initialize_creates_the_key_pair_and_a_gitignore_that_hides_only_the_private_key()
    {
        AuditStore store = AuditStore.Initialize(_root, out AuditSigner signer);
        using (signer)
        {
            Assert.True(File.Exists(store.PrivateKeyPath));
            Assert.True(File.Exists(store.PublicKeyPath));
            Assert.Equal("audit.key\n", File.ReadAllText(Path.Combine(store.Directory, ".gitignore")));
            Assert.Contains("PRIVATE KEY", File.ReadAllText(store.PrivateKeyPath));
            Assert.DoesNotContain("PRIVATE KEY", File.ReadAllText(store.PublicKeyPath));
        }
    }

    [Fact]
    public void Initialize_refuses_to_overwrite_an_existing_store()
    {
        AuditStore.Initialize(_root, out AuditSigner first);
        first.Dispose();
        string keyBefore = File.ReadAllText(Path.Combine(_root, ".deprisk", "audit.key"));

        Assert.Throws<AuditException>(() => AuditStore.Initialize(_root, out _));
        Assert.Equal(keyBefore, File.ReadAllText(Path.Combine(_root, ".deprisk", "audit.key")));
    }

    [Fact]
    public void The_private_key_is_readable_only_by_its_owner_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        AuditStore store = AuditStore.Initialize(_root, out AuditSigner signer);
        signer.Dispose();

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(store.PrivateKeyPath));
    }

    [Fact]
    public void Find_walks_up_to_the_project_that_owns_the_store()
    {
        AuditStore.Initialize(_root, out AuditSigner signer);
        signer.Dispose();
        string nested = Path.Combine(_root, "src", "deep");
        Directory.CreateDirectory(nested);

        AuditStore? found = AuditStore.Find(nested);

        Assert.NotNull(found);
        Assert.Equal(Path.Combine(_root, ".deprisk"), found!.Directory);
    }

    [Fact]
    public void A_directory_that_only_holds_a_gitignore_is_not_a_store()
    {
        Directory.CreateDirectory(Path.Combine(_root, ".deprisk"));
        File.WriteAllText(Path.Combine(_root, ".deprisk", ".gitignore"), "x\n");

        Assert.False(AuditStore.IsInitialized(_root));
    }

    [Fact]
    public void Loading_the_signer_without_a_key_is_an_audit_error()
    {
        AuditStore.Initialize(_root, out AuditSigner signer);
        signer.Dispose();
        AuditStore store = new(Path.Combine(_root, ".deprisk"));
        File.Delete(store.PrivateKeyPath);

        Assert.Throws<AuditException>(() => store.LoadSigner());
    }
}

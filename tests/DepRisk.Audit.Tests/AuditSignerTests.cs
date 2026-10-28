using System.Security.Cryptography;
using Xunit;

namespace DepRisk.Audit.Tests;

public sealed class AuditSignerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "deprisk-signer-" + Guid.NewGuid().ToString("N"));

    public AuditSignerTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void A_signature_verifies_and_is_88_base64_characters()
    {
        using AuditSigner signer = AuditSigner.Generate();

        string signature = signer.Sign("hello");

        Assert.Equal(88, signature.Length);
        Assert.EndsWith("==", signature);
        Assert.True(signer.Verify("hello", signature));
    }

    [Fact]
    public void Changed_text_or_a_changed_signature_does_not_verify()
    {
        using AuditSigner signer = AuditSigner.Generate();
        string signature = signer.Sign("hello");

        Assert.False(signer.Verify("hellO", signature));

        char[] chars = signature.ToCharArray();
        chars[10] = chars[10] == 'A' ? 'B' : 'A';
        Assert.False(signer.Verify("hello", new string(chars)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base64!!")]
    [InlineData("AAAA")]
    public void Malformed_signatures_are_rejected_without_throwing(string signature)
    {
        using AuditSigner signer = AuditSigner.Generate();

        Assert.False(signer.Verify("hello", signature));
    }

    [Fact]
    public void Another_key_does_not_verify()
    {
        using AuditSigner first = AuditSigner.Generate();
        using AuditSigner second = AuditSigner.Generate();

        Assert.False(second.Verify("hello", first.Sign("hello")));
    }

    [Fact]
    public void Keys_survive_a_round_trip_through_pem_files()
    {
        using AuditSigner original = AuditSigner.Generate();
        string privatePath = Path.Combine(_dir, "k.key");
        string publicPath = Path.Combine(_dir, "k.pub");
        File.WriteAllText(privatePath, original.ExportPrivatePem());
        File.WriteAllText(publicPath, original.ExportPublicPem());

        using AuditSigner priv = AuditSigner.LoadPrivate(privatePath);
        using AuditSigner pub = AuditSigner.LoadPublic(publicPath);

        Assert.True(pub.Verify("data", priv.Sign("data")));
        Assert.True(pub.Verify("data", original.Sign("data")));
    }

    [Fact]
    public void A_public_key_cannot_sign()
    {
        using AuditSigner original = AuditSigner.Generate();
        string publicPath = Path.Combine(_dir, "k.pub");
        File.WriteAllText(publicPath, original.ExportPublicPem());
        using AuditSigner pub = AuditSigner.LoadPublic(publicPath);

        Assert.Throws<AuditException>(() => pub.Sign("data"));
    }

    [Fact]
    public void Loading_a_public_key_as_private_fails()
    {
        using AuditSigner original = AuditSigner.Generate();
        string publicPath = Path.Combine(_dir, "k.pub");
        File.WriteAllText(publicPath, original.ExportPublicPem());

        Assert.Throws<AuditException>(() => AuditSigner.LoadPrivate(publicPath));
    }

    [Fact]
    public void Only_p256_keys_are_accepted()
    {
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        string path = Path.Combine(_dir, "p384.pub");
        File.WriteAllText(path, p384.ExportSubjectPublicKeyInfoPem());

        AuditException error = Assert.Throws<AuditException>(() => AuditSigner.LoadPublic(path));
        Assert.Contains("P-256", error.Message);
    }

    [Fact]
    public void Garbage_and_missing_files_are_audit_errors()
    {
        string garbage = Path.Combine(_dir, "garbage.pem");
        File.WriteAllText(garbage, "not a key");

        Assert.Throws<AuditException>(() => AuditSigner.LoadPublic(garbage));
        Assert.Throws<AuditException>(() => AuditSigner.LoadPublic(Path.Combine(_dir, "missing.pem")));
    }
}

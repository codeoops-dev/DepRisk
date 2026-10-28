using System.Security.Cryptography;
using System.Text;

namespace DepRisk.Audit;

/// <summary>
/// ECDSA over NIST P-256 with SHA-256 (see ADR 0005). Signatures are the raw 64-byte r||s form (IEEE P1363),
/// stored as standard Base64 (88 characters). Keys are stored as PEM (PKCS#8 private, SPKI public).
/// </summary>
public sealed class AuditSigner : IDisposable
{
    private const string P256Oid = "1.2.840.10045.3.1.7";
    private const int SignatureBytes = 64;

    private readonly ECDsa _key;
    private readonly bool _hasPrivateKey;

    private AuditSigner(ECDsa key, bool hasPrivateKey)
    {
        _key = key;
        _hasPrivateKey = hasPrivateKey;
    }

    public static AuditSigner Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256), hasPrivateKey: true);

    public static AuditSigner LoadPrivate(string path) => Load(path, privateKey: true);

    public static AuditSigner LoadPublic(string path) => Load(path, privateKey: false);

    public string ExportPrivatePem()
    {
        RequirePrivateKey();
        return _key.ExportPkcs8PrivateKeyPem() + "\n";
    }

    public string ExportPublicPem() => _key.ExportSubjectPublicKeyInfoPem() + "\n";

    /// <summary>Signs the UTF-8 bytes of <paramref name="canonicalBody"/>.</summary>
    public string Sign(string canonicalBody)
    {
        RequirePrivateKey();
        byte[] signature = _key.SignData(
            Encoding.UTF8.GetBytes(canonicalBody),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return Convert.ToBase64String(signature);
    }

    public bool Verify(string canonicalBody, string signatureBase64)
    {
        Span<byte> signature = stackalloc byte[SignatureBytes + 4];

        if (!Convert.TryFromBase64String(signatureBase64, signature, out int written) || written != SignatureBytes)
        {
            return false;
        }

        try
        {
            return _key.VerifyData(
                Encoding.UTF8.GetBytes(canonicalBody),
                signature[..written],
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public void Dispose() => _key.Dispose();

    private static AuditSigner Load(string path, bool privateKey)
    {
        string text;

        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new AuditException($"cannot read key file '{path}' ({ex.Message})", ex);
        }

        ECDsa key = ECDsa.Create();

        try
        {
            key.ImportFromPem(text);

            string? curve = key.ExportParameters(includePrivateParameters: false).Curve.Oid.Value;

            if (curve != P256Oid)
            {
                throw new AuditException($"key file '{path}' is not an ECDSA P-256 key.");
            }

            if (privateKey)
            {
                // Throws if the PEM only contained a public key.
                _ = key.ExportParameters(includePrivateParameters: true);
            }

            return new AuditSigner(key, hasPrivateKey: privateKey);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            key.Dispose();
            throw new AuditException($"key file '{path}' is not a valid {(privateKey ? "private" : "public")} key ({ex.Message})", ex);
        }
        catch (AuditException)
        {
            key.Dispose();
            throw;
        }
    }

    private void RequirePrivateKey()
    {
        if (!_hasPrivateKey)
        {
            throw new AuditException("this key has no private part and cannot sign.");
        }
    }
}

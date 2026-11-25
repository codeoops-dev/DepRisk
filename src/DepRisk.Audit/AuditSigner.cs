using System.Security.Cryptography;
using System.Text;

namespace DepRisk.Audit;

/// <summary>
/// ECDSA over NIST P-256 with SHA-256 (see ADR 0005). Signatures are the raw 64-byte r||s form (IEEE P1363),
/// stored as standard Base64 (88 characters). Keys are stored as PEM (PKCS#8 private, SPKI public). A private key can be encrypted
/// with a passphrase (PKCS#8 <c>ENCRYPTED PRIVATE KEY</c>, PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC), see ADR 0030.
/// </summary>
public sealed class AuditSigner : IDisposable
{
    private const string P256Oid = "1.2.840.10045.3.1.7";
    private const int SignatureBytes = 64;
    private const string EncryptedPemHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

    // 600,000 iterations of PBKDF2-HMAC-SHA256: the OWASP recommendation. It costs a few tenths of a second each time the key is loaded.
    private static readonly PbeParameters EncryptionParameters = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, iterationCount: 600_000);

    private readonly ECDsa _key;
    private readonly bool _hasPrivateKey;

    private AuditSigner(ECDsa key, bool hasPrivateKey)
    {
        _key = key;
        _hasPrivateKey = hasPrivateKey;
    }

    public static AuditSigner Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256), hasPrivateKey: true);

    /// <param name="passphrase">
    /// Called only when the key file is encrypted; returns the passphrase or null. A key file that is not encrypted never asks for
    /// one, so a passphrase that is set (or wrongly set) does not matter to it.
    /// </param>
    public static AuditSigner LoadPrivate(string path, Func<string?>? passphrase = null) => Load(path, privateKey: true, passphrase);

    public static AuditSigner LoadPublic(string path) => Load(path, privateKey: false, passphrase: null);

    /// <summary>True when the PEM text of a private key is encrypted.</summary>
    public static bool IsEncryptedKey(string pem) => pem.Contains(EncryptedPemHeader, StringComparison.Ordinal);

    /// <summary>The private key as an encrypted PKCS#8 PEM. The passphrase is never part of the output.</summary>
    public string ExportEncryptedPrivatePem(string passphrase)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        RequirePrivateKey();
        return _key.ExportEncryptedPkcs8PrivateKeyPem(passphrase, EncryptionParameters) + "\n";
    }

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

    /// <summary>
    /// Signs arbitrary bytes. The format is the caller's choice: the audit log uses the raw 64-byte form, while DSSE and Sigstore
    /// carry ASN.1 DER signatures (<see cref="DSASignatureFormat.Rfc3279DerSequence"/>), see ADR 0021.
    /// </summary>
    public byte[] SignBytes(ReadOnlySpan<byte> data, DSASignatureFormat format)
    {
        RequirePrivateKey();
        return _key.SignData(data, HashAlgorithmName.SHA256, format);
    }

    public bool VerifyBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, DSASignatureFormat format)
    {
        try
        {
            return _key.VerifyData(data, signature, HashAlgorithmName.SHA256, format);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// A stable identifier of the public key: the SHA-256 of its SubjectPublicKeyInfo (DER), as lowercase hexadecimal. It tells a
    /// verifier which key to look for; it is not a secret and not a proof of anything by itself.
    /// </summary>
    public string KeyId() => Convert.ToHexStringLower(SHA256.HashData(_key.ExportSubjectPublicKeyInfo()));

    public void Dispose() => _key.Dispose();

    private static AuditSigner Load(string path, bool privateKey, Func<string?>? passphrase)
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
            if (privateKey && IsEncryptedKey(text))
            {
                ImportEncrypted(key, text, path, passphrase);
            }
            else
            {
                key.ImportFromPem(text);
            }

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

    private static void ImportEncrypted(ECDsa key, string text, string path, Func<string?>? passphrase)
    {
        string? secret = passphrase?.Invoke();

        if (string.IsNullOrEmpty(secret))
        {
            throw new AuditException(
                $"the key file '{path}' is encrypted. Give its passphrase in {KeyPassphrase.EnvironmentVariable} or in the file named by {KeyPassphrase.FileEnvironmentVariable}.");
        }

        try
        {
            key.ImportFromEncryptedPem(text, secret);
        }
        catch (CryptographicException ex)
        {
            // Nothing from the exception is repeated: it can describe the data being decrypted.
            throw new AuditException($"cannot decrypt the key file '{path}': the passphrase is wrong or the file is damaged.", ex);
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

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DepRisk.Audit;

/// <summary>What a verified envelope contains.</summary>
public sealed record DsseVerification(string PayloadType, byte[] Payload, string? KeyId);

/// <summary>
/// DSSE (https://github.com/secure-systems-lab/dsse), the envelope Sigstore and in-toto use: the signature covers
/// <c>DSSEv1 &lt;len(type)&gt; &lt;type&gt; &lt;len(payload)&gt; &lt;payload&gt;</c>, so it binds the payload to its declared type and a signature
/// over something else (an audit entry, another document type) cannot be replayed as one. Signatures are ECDSA P-256 with SHA-256 in
/// ASN.1 DER form, which is what the Sigstore tooling and OpenSSL produce and expect (ADR 0021).
/// </summary>
public static class Dsse
{
    public const int MaxEnvelopeBytes = 64 * 1024 * 1024;
    private const int MaxSignatures = 16;

    /// <summary>The bytes that are signed.</summary>
    public static byte[] PreAuthenticationEncoding(string payloadType, ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(payloadType);

        byte[] type = Encoding.UTF8.GetBytes(payloadType);
        byte[] head = Encoding.ASCII.GetBytes(
            string.Create(CultureInfo.InvariantCulture, $"DSSEv1 {type.Length} "));
        byte[] middle = Encoding.ASCII.GetBytes(string.Create(CultureInfo.InvariantCulture, $" {payload.Length} "));

        byte[] result = new byte[head.Length + type.Length + middle.Length + payload.Length];
        head.CopyTo(result, 0);
        type.CopyTo(result, head.Length);
        middle.CopyTo(result, head.Length + type.Length);
        payload.CopyTo(result.AsSpan(head.Length + type.Length + middle.Length));
        return result;
    }

    /// <summary>The envelope as one line of JSON (a <c>.intoto.jsonl</c> file holds one such line per attestation).</summary>
    public static string Sign(AuditSigner signer, string payloadType, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(payload);

        byte[] signature = signer.SignBytes(PreAuthenticationEncoding(payloadType, payload), DSASignatureFormat.Rfc3279DerSequence);

        JsonObject envelope = new()
        {
            ["payloadType"] = payloadType,
            ["payload"] = Convert.ToBase64String(payload),
            ["signatures"] = new JsonArray(new JsonObject { ["keyid"] = signer.KeyId(), ["sig"] = Convert.ToBase64String(signature) }),
        };

        return envelope.ToJsonString() + "\n";
    }

    /// <summary>
    /// Checks the envelope against a public key: strict shape, and at least one signature that verifies. The key id in an envelope is a
    /// hint and is not trusted: only a signature that verifies with the key the caller supplied counts.
    /// </summary>
    /// <exception cref="AuditException">The envelope is malformed or no signature verifies.</exception>
    public static DsseVerification Verify(string envelopeJson, AuditSigner publicKey)
    {
        ArgumentNullException.ThrowIfNull(envelopeJson);
        ArgumentNullException.ThrowIfNull(publicKey);

        if (envelopeJson.Length > MaxEnvelopeBytes)
        {
            throw new AuditException("the envelope is larger than 64 MB.");
        }

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(envelopeJson, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException ex)
        {
            throw new AuditException($"the envelope is not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("payloadType", out JsonElement typeElement) || typeElement.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("payload", out JsonElement payloadElement) || payloadElement.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("signatures", out JsonElement signatures) || signatures.ValueKind != JsonValueKind.Array)
            {
                throw new AuditException("not a DSSE envelope (payloadType, payload, and signatures are required).");
            }

            string payloadType = typeElement.GetString()!;
            byte[] payload;

            try
            {
                payload = Convert.FromBase64String(payloadElement.GetString()!);
            }
            catch (FormatException ex)
            {
                throw new AuditException("the payload is not valid Base64.", ex);
            }

            int count = signatures.GetArrayLength();

            if (count is 0 or > MaxSignatures)
            {
                throw new AuditException($"an envelope must carry 1 to {MaxSignatures} signatures.");
            }

            byte[] signed = PreAuthenticationEncoding(payloadType, payload);

            foreach (JsonElement signatureElement in signatures.EnumerateArray())
            {
                if (signatureElement.ValueKind != JsonValueKind.Object
                    || !signatureElement.TryGetProperty("sig", out JsonElement sig) || sig.ValueKind != JsonValueKind.String)
                {
                    throw new AuditException("a signature entry has no 'sig'.");
                }

                byte[] bytes;

                try
                {
                    bytes = Convert.FromBase64String(sig.GetString()!);
                }
                catch (FormatException)
                {
                    continue;
                }

                if (publicKey.VerifyBytes(signed, bytes, DSASignatureFormat.Rfc3279DerSequence))
                {
                    string? keyId = signatureElement.TryGetProperty("keyid", out JsonElement id) && id.ValueKind == JsonValueKind.String ? id.GetString() : null;
                    return new DsseVerification(payloadType, payload, keyId);
                }
            }

            throw new AuditException("no signature in the envelope verifies with this public key.");
        }
    }
}

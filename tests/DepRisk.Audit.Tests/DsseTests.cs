using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace DepRisk.Audit.Tests;

public sealed class DsseTests
{
    private const string Type = "application/vnd.in-toto+json";

    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    [Fact]
    public void The_pre_authentication_encoding_is_the_one_of_the_dsse_specification()
    {
        // The example of the specification: payload type http://example.com/HelloWorld, payload "hello world".
        byte[] pae = Dsse.PreAuthenticationEncoding("http://example.com/HelloWorld", Bytes("hello world"));

        Assert.Equal("DSSEv1 29 http://example.com/HelloWorld 11 hello world", Encoding.UTF8.GetString(pae));
    }

    [Fact]
    public void Lengths_are_counted_in_bytes_not_characters()
    {
        byte[] pae = Dsse.PreAuthenticationEncoding("t", Bytes("é"));

        Assert.Equal("DSSEv1 1 t 2 é", Encoding.UTF8.GetString(pae));
    }

    [Fact]
    public void A_signed_envelope_verifies_with_the_public_key_and_returns_what_was_signed()
    {
        using AuditSigner signer = AuditSigner.Generate();
        string envelope = Dsse.Sign(signer, Type, Bytes("{\"a\":1}"));

        DsseVerification result = Dsse.Verify(envelope, signer);

        Assert.Equal(Type, result.PayloadType);
        Assert.Equal("{\"a\":1}", Encoding.UTF8.GetString(result.Payload));
        Assert.Equal(signer.KeyId(), result.KeyId);
        Assert.EndsWith("\n", envelope);
        Assert.DoesNotContain("\n", envelope.TrimEnd('\n'));
    }

    [Fact]
    public void The_signature_is_asn1_der_that_a_plain_ecdsa_implementation_verifies()
    {
        using AuditSigner signer = AuditSigner.Generate();
        using JsonDocument envelope = JsonDocument.Parse(Dsse.Sign(signer, Type, Bytes("payload")));
        byte[] signature = Convert.FromBase64String(envelope.RootElement.GetProperty("signatures")[0].GetProperty("sig").GetString()!);

        Assert.Equal(0x30, signature[0]);

        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(signer.ExportPublicPem());
        Assert.True(key.VerifyData(Dsse.PreAuthenticationEncoding(Type, Bytes("payload")), signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void Another_key_does_not_verify()
    {
        using AuditSigner signer = AuditSigner.Generate();
        using AuditSigner other = AuditSigner.Generate();

        AuditException ex = Assert.Throws<AuditException>(() => Dsse.Verify(Dsse.Sign(signer, Type, Bytes("x")), other));

        Assert.Contains("no signature", ex.Message);
    }

    [Fact]
    public void A_changed_payload_or_a_changed_payload_type_does_not_verify()
    {
        using AuditSigner signer = AuditSigner.Generate();
        JsonObject envelope = JsonNode.Parse(Dsse.Sign(signer, Type, Bytes("original")))!.AsObject();

        JsonObject payload = JsonNode.Parse(envelope.ToJsonString())!.AsObject();
        payload["payload"] = Convert.ToBase64String(Bytes("changed"));
        Assert.Throws<AuditException>(() => Dsse.Verify(payload.ToJsonString(), signer));

        // The type is part of what is signed, so a signature cannot be moved to a different kind of document.
        JsonObject retyped = JsonNode.Parse(envelope.ToJsonString())!.AsObject();
        retyped["payloadType"] = "text/plain";
        Assert.Throws<AuditException>(() => Dsse.Verify(retyped.ToJsonString(), signer));
    }

    [Fact]
    public void A_signature_made_for_the_audit_log_is_not_a_dsse_signature()
    {
        // Same key, same text: the audit log signs the raw text in the 64-byte form, DSSE signs the pre-authentication encoding in DER.
        using AuditSigner signer = AuditSigner.Generate();
        string payload = "{\"seq\":1}";
        string auditSignature = signer.Sign(payload);

        JsonObject envelope = new()
        {
            ["payloadType"] = Type,
            ["payload"] = Convert.ToBase64String(Bytes(payload)),
            ["signatures"] = new JsonArray(new JsonObject { ["sig"] = auditSignature }),
        };

        Assert.Throws<AuditException>(() => Dsse.Verify(envelope.ToJsonString(), signer));
    }

    [Fact]
    public void The_key_id_in_an_envelope_is_a_hint_and_decides_nothing()
    {
        using AuditSigner signer = AuditSigner.Generate();
        JsonObject envelope = JsonNode.Parse(Dsse.Sign(signer, Type, Bytes("x")))!.AsObject();

        // A wrong key id does not stop a valid signature from verifying...
        envelope["signatures"]![0]!["keyid"] = new string('0', 64);
        Assert.Equal(new string('0', 64), Dsse.Verify(envelope.ToJsonString(), signer).KeyId);

        // ...and the right key id does not make an invalid signature verify.
        using AuditSigner other = AuditSigner.Generate();
        envelope["signatures"]![0]!["keyid"] = other.KeyId();
        Assert.Throws<AuditException>(() => Dsse.Verify(envelope.ToJsonString(), other));
    }

    [Fact]
    public void An_envelope_with_several_signatures_verifies_if_one_of_them_does()
    {
        using AuditSigner signer = AuditSigner.Generate();
        using AuditSigner other = AuditSigner.Generate();
        JsonObject envelope = JsonNode.Parse(Dsse.Sign(signer, Type, Bytes("x")))!.AsObject();
        JsonObject foreign = JsonNode.Parse(Dsse.Sign(other, Type, Bytes("x")))!.AsObject();
        JsonArray signatures = envelope["signatures"]!.AsArray();
        signatures.Insert(0, JsonNode.Parse(foreign["signatures"]![0]!.ToJsonString()));

        Assert.Equal(Type, Dsse.Verify(envelope.ToJsonString(), signer).PayloadType);
        Assert.Equal(Type, Dsse.Verify(envelope.ToJsonString(), other).PayloadType);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"payloadType\":\"t\",\"payload\":\"eA==\"}")]
    [InlineData("{\"payloadType\":\"t\",\"payload\":\"eA==\",\"signatures\":[]}")]
    [InlineData("{\"payloadType\":\"t\",\"payload\":\"eA==\",\"signatures\":{}}")]
    [InlineData("{\"payloadType\":\"t\",\"payload\":\"!!\",\"signatures\":[{\"sig\":\"AA==\"}]}")]
    [InlineData("{\"payloadType\":\"t\",\"payload\":\"eA==\",\"signatures\":[{}]}")]
    [InlineData("{\"payloadType\":\"t\",\"payload\":\"eA==\",\"signatures\":[{\"sig\":\"not base64\"}]}")]
    [InlineData("{\"payloadType\":1,\"payload\":\"eA==\",\"signatures\":[{\"sig\":\"AA==\"}]}")]
    public void A_malformed_envelope_is_refused(string envelope)
    {
        using AuditSigner signer = AuditSigner.Generate();

        Assert.Throws<AuditException>(() => Dsse.Verify(envelope, signer));
    }

    [Fact]
    public void More_than_sixteen_signatures_are_refused()
    {
        using AuditSigner signer = AuditSigner.Generate();
        JsonObject envelope = JsonNode.Parse(Dsse.Sign(signer, Type, Bytes("x")))!.AsObject();
        JsonArray signatures = envelope["signatures"]!.AsArray();

        for (int i = 0; i < 16; i++)
        {
            signatures.Add(JsonNode.Parse(signatures[0]!.ToJsonString()));
        }

        Assert.Contains("1 to 16", Assert.Throws<AuditException>(() => Dsse.Verify(envelope.ToJsonString(), signer)).Message);
    }

    [Fact]
    public void A_public_key_cannot_sign()
    {
        using AuditSigner signer = AuditSigner.Generate();
        string pem = Path.Combine(Path.GetTempPath(), "deprisk-dsse-" + Guid.NewGuid().ToString("N") + ".pub");
        File.WriteAllText(pem, signer.ExportPublicPem());

        try
        {
            using AuditSigner publicOnly = AuditSigner.LoadPublic(pem);
            Assert.Throws<AuditException>(() => Dsse.Sign(publicOnly, Type, Bytes("x")));
            Assert.Equal(signer.KeyId(), publicOnly.KeyId());
            Assert.Equal(Type, Dsse.Verify(Dsse.Sign(signer, Type, Bytes("x")), publicOnly).PayloadType);
        }
        finally
        {
            File.Delete(pem);
        }
    }

    [Fact]
    public void The_key_id_is_the_sha256_of_the_public_key_in_hex_and_differs_between_keys()
    {
        using AuditSigner a = AuditSigner.Generate();
        using AuditSigner b = AuditSigner.Generate();

        Assert.Matches("^[0-9a-f]{64}$", a.KeyId());
        Assert.NotEqual(a.KeyId(), b.KeyId());
    }
}

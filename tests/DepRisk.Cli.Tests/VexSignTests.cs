using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DepRisk.Audit;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>vex --sign and vex verify (ADR 0021): a DSSE envelope with an in-toto statement that carries the OpenVEX document.</summary>
public sealed class VexSignTests : IDisposable
{
    private const string Timestamp = "2026-11-11T12:00:00Z";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-vex-sign-" + Guid.NewGuid().ToString("N"));

    private string Project => Path.Combine(_root, "proj");

    private string Osv => Path.Combine(_root, "osv");

    private string PrivateKey => Path.Combine(_root, "vex.key");

    private string PublicKey => Path.Combine(_root, "vex.pub");

    private string Subject => Path.Combine(_root, "app-1.0.0.nupkg");

    public VexSignTests()
    {
        Directory.CreateDirectory(Project);
        Directory.CreateDirectory(Osv);
        File.WriteAllText(Path.Combine(Project, "project.assets.json"), NpmFixtures.ReadReach("assets/project.assets.json"));

        foreach (string id in new[] { "0001", "0002", "0003" })
        {
            File.WriteAllText(Path.Combine(Osv, $"DEPRISK-EXAMPLE-{id}.json"), NpmFixtures.ReadReach($"osv/DEPRISK-EXAMPLE-{id}.json"));
        }

        using AuditSigner signer = AuditSigner.Generate();
        File.WriteAllText(PrivateKey, signer.ExportPrivatePem());
        File.WriteAllText(PublicKey, signer.ExportPublicPem());
        File.WriteAllText(Subject, "pretend this is a package");
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error, TestContext.For(_root));
        return (code, output.ToString(), error.ToString());
    }

    private string[] Vex(params string[] extra) =>
        ["vex", Project, "--advisories", Osv, "--product", "pkg:nuget/App@1.0.0", "--author", "tests", "--timestamp", Timestamp, .. extra];

    private string Sign(params string[] extra)
    {
        (int code, string output, string error) = Run(Vex(["--sign", "--key", PrivateKey, "--subject-file", Subject, .. extra]));
        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        return output;
    }

    private static JsonDocument Statement(string envelope)
    {
        using JsonDocument e = JsonDocument.Parse(envelope);
        return JsonDocument.Parse(Convert.FromBase64String(e.RootElement.GetProperty("payload").GetString()!));
    }

    [Fact]
    public void A_signed_document_is_a_dsse_envelope_around_an_in_toto_statement_that_carries_the_openvex_document()
    {
        string envelope = Sign();

        using JsonDocument e = JsonDocument.Parse(envelope);
        Assert.Equal("application/vnd.in-toto+json", e.RootElement.GetProperty("payloadType").GetString());
        Assert.Equal(1, e.RootElement.GetProperty("signatures").GetArrayLength());

        using JsonDocument statement = Statement(envelope);
        JsonElement root = statement.RootElement;
        Assert.Equal("https://in-toto.io/Statement/v1", root.GetProperty("_type").GetString());
        Assert.Equal("https://openvex.dev/ns/v0.2.0", root.GetProperty("predicateType").GetString());
        Assert.Equal("app-1.0.0.nupkg", root.GetProperty("subject")[0].GetProperty("name").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Subject))), root.GetProperty("subject")[0].GetProperty("digest").GetProperty("sha256").GetString());

        JsonElement vex = root.GetProperty("predicate");
        Assert.Equal("https://openvex.dev/ns/v0.2.0", vex.GetProperty("@context").GetString());
        Assert.Equal("tests", vex.GetProperty("author").GetString());
        Assert.Equal(3, vex.GetProperty("statements").GetArrayLength());
    }

    [Fact]
    public void The_predicate_is_exactly_the_unsigned_document()
    {
        (_, string unsigned, _) = Run(Vex());
        string envelope = Sign();

        using JsonDocument statement = Statement(envelope);

        // The same document; the statement carries it without indentation.
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(unsigned), JsonNode.Parse(statement.RootElement.GetProperty("predicate").GetRawText())));
    }

    [Fact]
    public void A_signed_document_verifies_with_the_public_key_and_names_what_it_is_about()
    {
        string envelope = Sign();
        string file = Path.Combine(_root, "vex.intoto.json");
        File.WriteAllText(file, envelope);

        (int code, string output, string error) = Run("vex", "verify", file, "--pubkey", PublicKey, "--subject-file", Subject);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Equal(string.Empty, error);
        Assert.StartsWith("OK: the signature verifies with the public key ", output);
        Assert.Contains("OpenVEX 0.2.0 by \"tests\": 3 statement(s)", output);
        Assert.Contains("about: app-1.0.0.nupkg sha256:", output);
        Assert.Contains("the file app-1.0.0.nupkg is one of the subjects", output);
        Assert.DoesNotContain(_root, output);
    }

    [Fact]
    public void The_digest_form_names_the_product_as_the_subject()
    {
        string digest = new('c', 64);
        (int code, string output, _) = Run(Vex(["--sign", "--key", PrivateKey, "--subject-digest", "sha256:" + digest]));

        Assert.Equal((int)ExitCode.Success, code);

        using JsonDocument statement = Statement(output);
        Assert.Equal("pkg:nuget/App@1.0.0", statement.RootElement.GetProperty("subject")[0].GetProperty("name").GetString());
        Assert.Equal(digest, statement.RootElement.GetProperty("subject")[0].GetProperty("digest").GetProperty("sha256").GetString());
    }

    [Fact]
    public void The_key_is_never_written_to_the_output_or_found_in_the_audit_log_arguments()
    {
        string envelope = Sign();

        Assert.DoesNotContain("PRIVATE KEY", envelope);
        Assert.Contains("***", string.Join(" ", ArgRedactor.Redact(Vex("--sign", "--key", PrivateKey, "--subject-file", Subject))));
        Assert.DoesNotContain(PrivateKey, string.Join(" ", ArgRedactor.Redact(Vex("--sign", "--key", PrivateKey))));
    }

    [Fact]
    public void Signing_needs_a_key_and_a_subject_and_the_signing_options_need_sign()
    {
        Assert.Contains("--sign needs --key", Run(Vex("--sign", "--subject-file", Subject)).Err);
        Assert.Contains("--sign needs the artifact", Run(Vex("--sign", "--key", PrivateKey)).Err);
        Assert.Contains("only apply together with --sign", Run(Vex("--key", PrivateKey)).Err);
        Assert.Contains("only apply together with --sign", Run(Vex("--subject-file", Subject)).Err);
        Assert.Contains("only apply together with --sign", Run(Vex("--subject-digest", "sha256:" + new string('a', 64))).Err);
    }

    [Theory]
    [InlineData("sha256:abc")]
    [InlineData("md5:0123456789abcdef0123456789abcdef")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    [InlineData("sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    public void A_malformed_digest_is_refused(string digest)
    {
        (int code, _, string error) = Run(Vex("--sign", "--key", PrivateKey, "--subject-digest", digest));

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Contains("--subject-digest must be sha256:", error);
    }

    [Fact]
    public void A_missing_key_or_subject_file_or_a_public_key_in_place_of_the_private_one_is_refused()
    {
        (int missingKey, _, string keyError) = Run(Vex("--sign", "--key", Path.Combine(_root, "nope.key"), "--subject-file", Subject));
        Assert.Equal((int)ExitCode.InvalidInput, missingKey);
        Assert.Contains("cannot read key file", keyError);

        (int publicOnly, _, string publicError) = Run(Vex("--sign", "--key", PublicKey, "--subject-file", Subject));
        Assert.Equal((int)ExitCode.InvalidInput, publicOnly);
        Assert.Contains("is not a valid private key", publicError);

        (int missingSubject, _, string subjectError) = Run(Vex("--sign", "--key", PrivateKey, "--subject-file", Path.Combine(_root, "nope.bin")));
        Assert.Equal((int)ExitCode.InvalidInput, missingSubject);
        Assert.Contains("cannot read the subject file", subjectError);
    }

    [Fact]
    public void A_changed_document_does_not_verify_and_exits_with_the_integrity_failure_code()
    {
        JsonObject envelope = JsonNode.Parse(Sign())!.AsObject();
        JsonObject statement = JsonNode.Parse(Convert.FromBase64String(envelope["payload"]!.GetValue<string>()))!.AsObject();
        statement["predicate"]!["author"] = "someone else";
        envelope["payload"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(statement.ToJsonString()));
        string file = Path.Combine(_root, "tampered.json");
        File.WriteAllText(file, envelope.ToJsonString());

        (int code, string output, string error) = Run("vex", "verify", file, "--pubkey", PublicKey);

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("no signature in the envelope verifies", error);
    }

    [Fact]
    public void Another_public_key_does_not_verify()
    {
        string file = Path.Combine(_root, "vex.json");
        File.WriteAllText(file, Sign());
        string otherPublic = Path.Combine(_root, "other.pub");

        using (AuditSigner other = AuditSigner.Generate())
        {
            File.WriteAllText(otherPublic, other.ExportPublicPem());
        }

        (int code, _, string error) = Run("vex", "verify", file, "--pubkey", otherPublic);

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Contains("no signature", error);
    }

    [Fact]
    public void A_document_about_another_file_does_not_verify_against_it()
    {
        string file = Path.Combine(_root, "vex.json");
        File.WriteAllText(file, Sign());
        string other = Path.Combine(_root, "other.nupkg");
        File.WriteAllText(other, "something else");

        (int code, _, string error) = Run("vex", "verify", file, "--pubkey", PublicKey, "--subject-file", other);

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Contains("is not among the subjects", error);
    }

    [Fact]
    public void A_signed_document_of_another_kind_is_not_taken_for_openvex()
    {
        using AuditSigner signer = AuditSigner.LoadPrivate(PrivateKey);
        string file = Path.Combine(_root, "other-kind.json");

        // Validly signed, but the predicate is not OpenVEX.
        File.WriteAllText(file, Dsse.Sign(signer, InTotoStatement.PayloadType, InTotoStatement.Create([new AttestationSubject("x", new string('a', 64))], "https://example.com/other/v1", "{\"a\":1}")));
        (int code, _, string error) = Run("vex", "verify", file, "--pubkey", PublicKey);
        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Contains("not about OpenVEX", error);

        // Validly signed, but not an in-toto statement at all.
        File.WriteAllText(file, Dsse.Sign(signer, "text/plain", Encoding.UTF8.GetBytes("hello")));
        (int plain, _, string plainError) = Run("vex", "verify", file, "--pubkey", PublicKey);
        Assert.Equal((int)ExitCode.AuditIntegrityFailure, plain);
        Assert.Contains("not an in-toto statement", plainError);
    }

    [Fact]
    public void Verify_needs_an_envelope_and_a_key_and_reads_both_safely()
    {
        string file = Path.Combine(_root, "vex.json");
        File.WriteAllText(file, Sign());

        Assert.Contains("needs the signed document", Run("vex", "verify", "--pubkey", PublicKey).Err);
        Assert.Contains("needs --pubkey", Run("vex", "verify", file).Err);
        Assert.Contains("unknown option '--nope'", Run("vex", "verify", file, "--pubkey", PublicKey, "--nope").Err);
        Assert.Contains("takes one envelope file", Run("vex", "verify", file, file, "--pubkey", PublicKey).Err);
        Assert.Contains("cannot read", Run("vex", "verify", Path.Combine(_root, "nope.json"), "--pubkey", PublicKey).Err);
        Assert.Contains("cannot read key file", Run("vex", "verify", file, "--pubkey", Path.Combine(_root, "nope.pub")).Err);
        Assert.Equal((int)ExitCode.InvalidInput, Run("vex", "verify", file, "--pubkey", PrivateKey.Replace("vex.key", "missing")).Code);

        // A private key is not a public key to trust with: only its public part matters, and the file must be a key.
        string junk = Path.Combine(_root, "junk.pub");
        File.WriteAllText(junk, "not a key");
        Assert.Equal((int)ExitCode.InvalidInput, Run("vex", "verify", file, "--pubkey", junk).Code);
    }

    [Fact]
    public void A_file_that_is_not_an_envelope_is_an_integrity_failure_not_a_crash()
    {
        string file = Path.Combine(_root, "junk.json");
        File.WriteAllText(file, "{ \"hello\": 1 }");

        (int code, _, string error) = Run("vex", "verify", file, "--pubkey", PublicKey);

        Assert.Equal((int)ExitCode.AuditIntegrityFailure, code);
        Assert.Contains("not a DSSE envelope", error);
    }

    [Fact]
    public void The_out_option_writes_the_envelope_to_a_file_and_says_what_it_wrote()
    {
        string file = Path.Combine(_root, "out.json");

        (int code, string output, _) = Run(Vex(["--sign", "--key", PrivateKey, "--subject-file", Subject, "--out", file]));

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Wrote signed OpenVEX (DSSE envelope, in-toto statement) to", output);
        Assert.Equal((int)ExitCode.Success, Run("vex", "verify", file, "--pubkey", PublicKey).Code);
    }

    [Fact]
    public void A_key_made_by_openssl_in_sec1_form_also_signs()
    {
        // `openssl ecparam -genkey -name prime256v1` writes "EC PRIVATE KEY" (SEC1), not PKCS#8.
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sec1 = Path.Combine(_root, "sec1.key");
        File.WriteAllText(sec1, key.ExportECPrivateKeyPem());
        string pub = Path.Combine(_root, "sec1.pub");
        File.WriteAllText(pub, key.ExportSubjectPublicKeyInfoPem());

        (int code, string envelope, _) = Run(Vex(["--sign", "--key", sec1, "--subject-file", Subject]));
        Assert.Equal((int)ExitCode.Success, code);

        string file = Path.Combine(_root, "sec1.json");
        File.WriteAllText(file, envelope);
        Assert.Equal((int)ExitCode.Success, Run("vex", "verify", file, "--pubkey", pub).Code);
    }
}

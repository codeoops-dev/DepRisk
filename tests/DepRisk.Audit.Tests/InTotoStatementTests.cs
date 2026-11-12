using System.Text;
using System.Text.Json;
using Xunit;

namespace DepRisk.Audit.Tests;

public sealed class InTotoStatementTests
{
    private static readonly string Digest = new('a', 64);

    private static readonly AttestationSubject[] One = [new AttestationSubject("app.tar", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")];

    [Fact]
    public void A_statement_has_the_in_toto_v1_shape()
    {
        byte[] payload = InTotoStatement.Create(One, "https://openvex.dev/ns/v0.2.0", "{\"@context\":\"x\",\"statements\":[]}");

        using JsonDocument document = JsonDocument.Parse(payload);
        JsonElement root = document.RootElement;

        Assert.Equal("https://in-toto.io/Statement/v1", root.GetProperty("_type").GetString());
        Assert.Equal("https://openvex.dev/ns/v0.2.0", root.GetProperty("predicateType").GetString());
        Assert.Equal("app.tar", root.GetProperty("subject")[0].GetProperty("name").GetString());
        Assert.Equal(One[0].Sha256, root.GetProperty("subject")[0].GetProperty("digest").GetProperty("sha256").GetString());
        Assert.Equal("x", root.GetProperty("predicate").GetProperty("@context").GetString());
    }

    [Fact]
    public void A_created_statement_parses_back_with_its_predicate_untouched()
    {
        StatementInfo info = InTotoStatement.Parse(InTotoStatement.Create(One, "urn:type", "{\"a\":[1,2,{\"b\":null}]}"));

        Assert.Equal("urn:type", info.PredicateType);
        Assert.Equal(One[0], Assert.Single(info.Subjects));
        Assert.Equal("{\"a\":[1,2,{\"b\":null}]}", info.PredicateJson);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")]
    [InlineData("0123")]
    [InlineData("zzzz456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    public void A_digest_must_be_64_lowercase_hex_digits(string digest)
    {
        Assert.False(InTotoStatement.IsDigest(digest));
        Assert.Throws<AuditException>(() => InTotoStatement.Create([new AttestationSubject("x", digest)], "t", "{}"));
    }

    [Fact]
    public void Subjects_need_a_clean_name_and_there_must_be_between_one_and_one_hundred()
    {
        Assert.Throws<AuditException>(() => InTotoStatement.Create([], "t", "{}"));
        Assert.Throws<AuditException>(() => InTotoStatement.Create([new AttestationSubject(" ", Digest)], "t", "{}"));
        Assert.Throws<AuditException>(() => InTotoStatement.Create([new AttestationSubject("a\u001bb", Digest)], "t", "{}"));
        Assert.Throws<AuditException>(() => InTotoStatement.Create([new AttestationSubject(new string('n', 501), Digest)], "t", "{}"));
        Assert.Throws<AuditException>(() => InTotoStatement.Create(Enumerable.Range(0, 101).Select(i => new AttestationSubject("s" + i, Digest)).ToList(), "t", "{}"));
        Assert.Equal(100, InTotoStatement.Parse(InTotoStatement.Create(Enumerable.Range(0, 100).Select(i => new AttestationSubject("s" + i, Digest)).ToList(), "t", "{}")).Subjects.Count);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"_type\":\"https://in-toto.io/Statement/v0.1\",\"subject\":[],\"predicateType\":\"t\",\"predicate\":{}}")]
    [InlineData("{\"_type\":\"https://in-toto.io/Statement/v1\",\"predicateType\":\"t\",\"predicate\":{}}")]
    [InlineData("{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[],\"predicateType\":\"t\",\"predicate\":{}}")]
    [InlineData("{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"x\"}],\"predicateType\":\"t\",\"predicate\":{}}")]
    [InlineData("{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"x\",\"digest\":{\"sha1\":\"aa\"}}],\"predicateType\":\"t\",\"predicate\":{}}")]
    [InlineData("{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"x\",\"digest\":{\"sha256\":\"short\"}}],\"predicateType\":\"t\",\"predicate\":{}}")]
    public void A_payload_that_is_not_a_statement_of_this_version_is_refused(string payload)
    {
        Assert.Throws<AuditException>(() => InTotoStatement.Parse(Encoding.UTF8.GetBytes(payload)));
    }

    [Fact]
    public void A_statement_without_a_predicate_type_or_with_a_non_object_predicate_is_refused()
    {
        string subject = "\"subject\":[{\"name\":\"x\",\"digest\":{\"sha256\":\"" + Digest + "\"}}]";

        Assert.Throws<AuditException>(() => InTotoStatement.Parse(Encoding.UTF8.GetBytes("{\"_type\":\"https://in-toto.io/Statement/v1\"," + subject + ",\"predicate\":{}}")));
        Assert.Throws<AuditException>(() => InTotoStatement.Parse(Encoding.UTF8.GetBytes("{\"_type\":\"https://in-toto.io/Statement/v1\"," + subject + ",\"predicateType\":\"t\",\"predicate\":[]}")));
        Assert.Throws<AuditException>(() => InTotoStatement.Parse(Encoding.UTF8.GetBytes("{\"_type\":\"https://in-toto.io/Statement/v1\"," + subject + ",\"predicateType\":\"t\"}")));
    }

    [Fact]
    public void An_empty_predicate_text_is_refused()
    {
        Assert.Throws<AuditException>(() => InTotoStatement.Create(One, "t", "null"));
    }
}

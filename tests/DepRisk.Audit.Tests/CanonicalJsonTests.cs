using Xunit;

namespace DepRisk.Audit.Tests;

public class CanonicalJsonTests
{
    private static AuditEntry Sample(string actor = "alice") => new(
        Seq: 7,
        Timestamp: "2026-10-27T12:00:00.000Z",
        Actor: actor,
        Host: "host-1",
        Cwd: "/work/project",
        GitCommit: null,
        Command: "scan",
        Args: ["--format", "json"],
        InputsDigest: new string('a', 64),
        OutputsDigest: new string('b', 64),
        Changes: [new AuditChange("out.json", null, "written")],
        PrevHash: new string('0', 64),
        Signature: "SIG");

    [Fact]
    public void Full_form_is_compact_with_keys_in_ordinal_order()
    {
        string expected =
            "{\"actor\":\"alice\",\"args\":[\"--format\",\"json\"],"
            + "\"changes\":[{\"from\":null,\"subject\":\"out.json\",\"to\":\"written\"}],"
            + "\"command\":\"scan\",\"cwd\":\"/work/project\",\"gitCommit\":null,\"host\":\"host-1\","
            + "\"inputsDigest\":\"" + new string('a', 64) + "\",\"outputsDigest\":\"" + new string('b', 64) + "\","
            + "\"prevHash\":\"" + new string('0', 64) + "\",\"schemaVersion\":1,\"seq\":7,\"signature\":\"SIG\","
            + "\"timestamp\":\"2026-10-27T12:00:00.000Z\"}";

        Assert.Equal(expected, CanonicalJson.Full(Sample()));
    }

    [Fact]
    public void Body_is_the_full_form_without_the_signature()
    {
        string body = CanonicalJson.Body(Sample());

        Assert.DoesNotContain("signature", body);
        Assert.Contains("\"seq\":7,\"timestamp\"", body);
    }

    [Fact]
    public void Strings_use_only_the_minimal_escapes()
    {
        string json = CanonicalJson.Body(Sample("a\"b\\c\n\t\u0001é<>&'"));

        Assert.Contains("\"actor\":\"a\\\"b\\\\c\\n\\t\\u0001é<>&'\"", json);
    }

    [Fact]
    public void A_lone_surrogate_is_replaced_so_the_text_is_valid_utf8()
    {
        string json = CanonicalJson.Body(Sample("x\uD800y"));

        Assert.Contains("\"actor\":\"x\uFFFDy\"", json);
    }

    [Fact]
    public void A_valid_surrogate_pair_is_kept()
    {
        string json = CanonicalJson.Body(Sample("😀"));

        Assert.Contains("\"actor\":\"😀\"", json);
    }

    [Fact]
    public void Same_entry_always_gives_the_same_bytes()
    {
        Assert.Equal(CanonicalJson.Full(Sample()), CanonicalJson.Full(Sample()));
    }
}

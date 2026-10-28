using System.Text.Json;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Audit.Tests;

public class AuditLogTests
{
    [Fact]
    public void An_empty_log_verifies_with_zero_entries_and_the_zero_head()
    {
        using TempStore store = new();
        File.WriteAllText(store.Store.LogPath, string.Empty);

        AuditVerification result = store.Verify();

        Assert.True(result.Ok);
        Assert.Equal(0, result.Entries);
        Assert.Equal(Digest.ZeroHash, result.Head);
    }

    [Fact]
    public void Entries_are_numbered_from_one_and_chained_by_hash()
    {
        using TempStore store = new();

        AuditEntry first = store.Append();
        AuditEntry second = store.Append("plan", "--budget", "6h");
        AuditEntry third = store.Append();

        Assert.Equal(new[] { 1, 2, 3 }, new[] { first.Seq, second.Seq, third.Seq });
        Assert.Equal(Digest.ZeroHash, first.PrevHash);

        string[] lines = store.Lines();
        Assert.Equal(Digest.Sha256Hex(lines[0]), second.PrevHash);
        Assert.Equal(Digest.Sha256Hex(lines[1]), third.PrevHash);
    }

    [Fact]
    public void A_clean_log_verifies_and_reports_its_head()
    {
        using TempStore store = new();
        store.Append();
        store.Append();
        store.Append();

        AuditVerification result = store.Verify();

        Assert.True(result.Ok);
        Assert.Equal(3, result.Entries);
        Assert.Equal(Digest.Sha256Hex(store.Lines()[2]), result.Head);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Every_line_has_exactly_the_documented_properties()
    {
        using TempStore store = new();
        store.Append();

        using JsonDocument document = JsonDocument.Parse(store.Lines()[0]);
        string[] names = document.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).ToArray();

        Assert.Equal(
            new[]
            {
                "actor", "args", "changes", "command", "cwd", "gitCommit", "host", "inputsDigest", "outputsDigest",
                "prevHash", "schemaVersion", "seq", "signature", "timestamp",
            },
            names);
    }

    [Fact]
    public void Editing_any_field_of_an_entry_is_detected()
    {
        using TempStore store = new();
        store.Append();
        store.Append();
        store.Append();

        string[] lines = store.Lines();
        lines[1] = lines[1].Replace("\"actor\":\"alice\"", "\"actor\":\"mallory\"", StringComparison.Ordinal);
        store.WriteLines(lines);

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Equal(2, result.FailedLine);
        Assert.Contains("signature", result.Error);
    }

    [Fact]
    public void Deleting_an_entry_in_the_middle_is_detected()
    {
        using TempStore store = new();
        store.Append();
        store.Append();
        store.Append();

        string[] lines = store.Lines();
        store.WriteLines([lines[0], lines[2]]);

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Equal(2, result.FailedLine);
        Assert.Contains("sequence", result.Error);
    }

    [Fact]
    public void Reordering_entries_is_detected()
    {
        using TempStore store = new();
        store.Append();
        store.Append();
        store.Append();

        string[] lines = store.Lines();
        store.WriteLines([lines[0], lines[2], lines[1]]);

        Assert.False(store.Verify().Ok);
    }

    [Fact]
    public void Removing_the_first_entry_is_detected()
    {
        using TempStore store = new();
        store.Append();
        store.Append();

        store.WriteLines(store.Lines().Skip(1));

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Equal(1, result.FailedLine);
    }

    [Fact]
    public void Replacing_an_entry_with_one_signed_by_another_key_is_detected()
    {
        using TempStore store = new();
        store.Append();
        store.Append();

        using TempStore other = new();
        other.Append();
        other.Append();

        string[] mine = store.Lines();
        string[] theirs = other.Lines();
        store.WriteLines([mine[0], theirs[1]]);

        Assert.False(store.Verify().Ok);
    }

    [Fact]
    public void A_wrong_public_key_fails_verification()
    {
        using TempStore store = new();
        store.Append();

        using AuditSigner stranger = AuditSigner.Generate();
        AuditVerification result = AuditLog.Verify(store.Store.LogPath, stranger);

        Assert.False(result.Ok);
        Assert.Contains("signature", result.Error);
    }

    [Fact]
    public void Extra_unsigned_properties_are_rejected()
    {
        using TempStore store = new();
        store.Append();

        string line = store.Lines()[0];
        store.WriteLines([line.TrimEnd('}') + ",\"note\":\"injected\"}"]);

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Contains("unexpected property", result.Error);
    }

    [Fact]
    public void Re_serialized_whitespace_is_rejected_because_only_the_canonical_form_is_valid()
    {
        using TempStore store = new();
        store.Append();

        // Same content, one extra space: the signature is still mathematically valid for the data,
        // but the stored line is no longer the canonical serialization.
        store.WriteLines([store.Lines()[0].Replace("{\"actor\"", "{ \"actor\"", StringComparison.Ordinal)]);

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Contains("canonical", result.Error);
    }

    [Fact]
    public void Garbage_lines_are_reported_with_their_line_number()
    {
        using TempStore store = new();
        store.Append();
        File.AppendAllText(store.Store.LogPath, "this is not json\n");

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Equal(2, result.FailedLine);
    }

    [Fact]
    public void An_unfinished_last_line_is_reported()
    {
        using TempStore store = new();
        store.Append();
        store.Append();

        string text = File.ReadAllText(store.Store.LogPath);
        File.WriteAllText(store.Store.LogPath, text[..^30]);

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Contains("incomplete", result.Error);
    }

    [Fact]
    public void Cutting_entries_off_the_end_is_only_noticed_when_the_head_is_pinned()
    {
        using TempStore store = new();
        store.Append();
        store.Append();
        store.Append();

        string pinnedHead = store.Verify().Head;
        store.WriteLines(store.Lines().Take(2));

        Assert.True(store.Verify().Ok);

        AuditVerification pinned = store.Verify(pinnedHead);
        Assert.False(pinned.Ok);
        Assert.Contains("head", pinned.Error);
    }

    [Fact]
    public void A_pinned_head_that_matches_passes()
    {
        using TempStore store = new();
        store.Append();
        store.Append();

        Assert.True(store.Verify(store.Verify().Head).Ok);
    }

    [Fact]
    public void A_missing_log_is_reported()
    {
        using TempStore store = new();

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Contains("not found", result.Error);
    }

    [Fact]
    public void Appending_to_a_damaged_log_is_refused_instead_of_extending_it()
    {
        using TempStore store = new();
        store.Append();
        File.AppendAllText(store.Store.LogPath, "{\"half\":");

        Assert.Throws<AuditException>(() => store.Append());
    }

    [Fact]
    public void Appending_continues_the_chain_after_the_log_was_reopened()
    {
        using TempStore store = new();
        store.Append();
        store.Append();

        AuditLog reopened = new(store.Store);
        AuditEntry next = reopened.Append(
            new AuditDraft("scan", [], new string('a', 64), new string('b', 64), []),
            TempStore.Environment(),
            store.Signer);

        Assert.Equal(3, next.Seq);
        Assert.True(store.Verify().Ok);
    }

    [Fact]
    public void Parallel_appends_never_fork_the_chain()
    {
        using TempStore store = new();

        Parallel.For(0, 12, i =>
        {
            AuditLog log = new(store.Store);
            log.Append(
                new AuditDraft("scan", [i.ToString(System.Globalization.CultureInfo.InvariantCulture)], new string('a', 64), new string('b', 64), []),
                TempStore.Environment(),
                store.Signer);
        });

        AuditVerification result = store.Verify();

        Assert.True(result.Ok, result.Error);
        Assert.Equal(12, result.Entries);
    }

    [Fact]
    public void Unicode_and_awkward_text_survive_the_round_trip()
    {
        using TempStore store = new();
        AuditDraft draft = new(
            "scan",
            ["C:\\Users\\Jahed Kabiri\\پروژه", "quote\"inside", "tab\tnewline\n", "😀"],
            new string('a', 64),
            new string('b', 64),
            [new AuditChange("مسیر/فایل.json", "old \"value\"", null)]);

        store.Log.Append(draft, TempStore.Environment(), store.Signer);

        Assert.True(store.Verify().Ok);
    }
}

using DepRisk.Core;
using Xunit;

namespace DepRisk.Audit.Tests;

/// <summary>Verification reads the log in blocks and holds one line at a time (S26).</summary>
public class AuditVerifyStreamingTests
{
    [Fact]
    public void A_log_many_blocks_long_verifies_and_every_entry_is_counted()
    {
        using TempStore store = new();

        for (int i = 0; i < 600; i++)
        {
            store.Append("scan", "--format", "json");
        }

        Assert.True(new FileInfo(store.Store.LogPath).Length > 5 * 64 * 1024, "the log must span several blocks");

        AuditVerification result = store.Verify();

        Assert.True(result.Ok, result.Error);
        Assert.Equal(600, result.Entries);
        Assert.Equal(Digest.Sha256Hex(store.Lines()[599]), result.Head);
    }

    [Fact]
    public void A_change_deep_in_a_long_log_is_found_at_its_line()
    {
        using TempStore store = new();

        for (int i = 0; i < 400; i++)
        {
            store.Append();
        }

        string[] lines = store.Lines();
        lines[321] = lines[321].Replace("\"actor\":\"alice\"", "\"actor\":\"mallory\"", StringComparison.Ordinal);
        store.WriteLines(lines);

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Equal(322, result.FailedLine);
        Assert.Equal(321, result.Entries);
    }

    [Fact]
    public void An_entry_that_is_too_large_is_a_failure_at_its_line_and_is_never_held_whole()
    {
        using TempStore store = new();
        store.Append();
        string[] lines = store.Lines();
        File.WriteAllText(store.Store.LogPath, lines[0] + "\n" + new string('x', 3 * 1024 * 1024) + "\n");

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Equal(2, result.FailedLine);
        Assert.Equal("entry is too large", result.Error);
        Assert.Equal(1, result.Entries);
    }

    [Fact]
    public void A_last_entry_without_a_line_ending_is_reported_with_its_line_number()
    {
        using TempStore store = new();
        store.Append();
        store.Append();
        string text = File.ReadAllText(store.Store.LogPath);
        File.WriteAllText(store.Store.LogPath, text.TrimEnd('\n'));

        AuditVerification result = store.Verify();

        Assert.False(result.Ok);
        Assert.Equal(2, result.FailedLine);
        Assert.Contains("incomplete", result.Error);
    }

    [Fact]
    public void An_expected_head_is_still_checked_after_a_streamed_pass()
    {
        using TempStore store = new();
        store.Append();
        store.Append();

        Assert.True(store.Verify(Digest.Sha256Hex(store.Lines()[1])).Ok);
        Assert.False(store.Verify(Digest.Sha256Hex(store.Lines()[0])).Ok);
    }

    [Fact]
    public void Verification_does_not_lock_the_log_while_it_reads_or_afterwards()
    {
        using TempStore store = new();
        store.Append();

        // A writer that holds the file open for reading and writing does not stop a verification (and an append is not made to wait).
        using (FileStream writer = new(store.Store.LogPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            Assert.True(store.Verify().Ok);
        }

        store.Append();
        Assert.True(store.Verify().Ok);
        File.Delete(store.Store.LogPath);
    }

    [Fact]
    public void A_new_entry_is_seen_by_the_next_verification_and_not_by_the_one_before()
    {
        using TempStore store = new();
        store.Append();
        store.Append();
        AuditVerification before = store.Verify();

        store.Append();

        Assert.Equal(2, before.Entries);
        Assert.Equal(3, store.Verify().Entries);
    }
}

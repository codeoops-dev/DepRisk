using Xunit;

namespace DepRisk.Audit.Tests;

public sealed class GitHeadTests : IDisposable
{
    private const string Commit = "0123456789abcdef0123456789abcdef01234567";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-git-" + Guid.NewGuid().ToString("N"));

    public GitHeadTests() => Directory.CreateDirectory(Path.Combine(_root, ".git", "refs", "heads"));

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private void Head(string content) => File.WriteAllText(Path.Combine(_root, ".git", "HEAD"), content);

    [Fact]
    public void A_detached_head_is_read_directly()
    {
        Head(Commit + "\n");

        Assert.Equal(Commit, GitHead.TryReadCommit(_root));
    }

    [Fact]
    public void A_branch_is_followed_to_its_loose_ref()
    {
        Head("ref: refs/heads/main\n");
        File.WriteAllText(Path.Combine(_root, ".git", "refs", "heads", "main"), Commit + "\n");

        Assert.Equal(Commit, GitHead.TryReadCommit(_root));
    }

    [Fact]
    public void A_packed_ref_is_found_when_there_is_no_loose_ref()
    {
        Head("ref: refs/heads/main\n");
        File.WriteAllText(
            Path.Combine(_root, ".git", "packed-refs"),
            "# pack-refs with: peeled\n" + "ffffffffffffffffffffffffffffffffffffffff refs/heads/other\n" + Commit + " refs/heads/main\n");

        Assert.Equal(Commit, GitHead.TryReadCommit(_root));
    }

    [Fact]
    public void Subdirectories_find_the_repository_above_them()
    {
        Head(Commit);
        string nested = Path.Combine(_root, "a", "b");
        Directory.CreateDirectory(nested);

        Assert.Equal(Commit, GitHead.TryReadCommit(nested));
    }

    [Theory]
    [InlineData("ref: refs/heads/../../../etc/passwd")]
    [InlineData("ref: /etc/passwd")]
    [InlineData("ref: heads/main")]
    [InlineData("garbage")]
    [InlineData("")]
    public void Unsafe_or_unclear_heads_give_null(string content)
    {
        Head(content);

        Assert.Null(GitHead.TryReadCommit(_root));
    }

    [Fact]
    public void An_unborn_branch_gives_null()
    {
        Head("ref: refs/heads/main\n");

        Assert.Null(GitHead.TryReadCommit(_root));
    }
}

namespace DepRisk.Audit;

/// <summary>
/// Reads the current commit by looking at files in <c>.git</c>. It never runs <c>git</c> and never follows
/// references outside the git directory. Returns null whenever the answer is not clear.
/// </summary>
public static class GitHead
{
    public static string? TryReadCommit(string startDirectory)
    {
        try
        {
            DirectoryInfo? current = new(Path.GetFullPath(startDirectory));

            while (current is not null)
            {
                string gitPath = Path.Combine(current.FullName, ".git");

                if (Directory.Exists(gitPath))
                {
                    return ReadFromGitDirectory(gitPath);
                }

                if (File.Exists(gitPath))
                {
                    // A worktree or submodule ".git" file points elsewhere; not supported yet.
                    return null;
                }

                current = current.Parent;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }

        return null;
    }

    private static string? ReadFromGitDirectory(string gitDirectory)
    {
        string head = File.ReadAllText(Path.Combine(gitDirectory, "HEAD")).Trim();

        if (IsCommitId(head))
        {
            return head.ToLowerInvariant();
        }

        const string prefix = "ref: ";

        if (!head.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        string reference = head[prefix.Length..].Trim();

        if (!IsSafeReference(reference))
        {
            return null;
        }

        string loosePath = Path.GetFullPath(Path.Combine(gitDirectory, reference));
        string root = Path.GetFullPath(gitDirectory) + Path.DirectorySeparatorChar;

        if (loosePath.StartsWith(root, StringComparison.Ordinal) && File.Exists(loosePath))
        {
            string loose = File.ReadAllText(loosePath).Trim();
            return IsCommitId(loose) ? loose.ToLowerInvariant() : null;
        }

        string packed = Path.Combine(gitDirectory, "packed-refs");

        if (!File.Exists(packed))
        {
            return null;
        }

        foreach (string line in File.ReadLines(packed))
        {
            if (line.Length == 0 || line[0] is '#' or '^')
            {
                continue;
            }

            int space = line.IndexOf(' ', StringComparison.Ordinal);

            if (space > 0
                && string.Equals(line[(space + 1)..].Trim(), reference, StringComparison.Ordinal)
                && IsCommitId(line[..space]))
            {
                return line[..space].ToLowerInvariant();
            }
        }

        return null;
    }

    private static bool IsSafeReference(string reference) =>
        reference.StartsWith("refs/", StringComparison.Ordinal)
        && !reference.Contains("..", StringComparison.Ordinal)
        && !reference.Contains('\\', StringComparison.Ordinal)
        && !reference.Any(char.IsControl);

    private static bool IsCommitId(string value) =>
        value.Length is 40 or 64 && value.All(char.IsAsciiHexDigit);
}

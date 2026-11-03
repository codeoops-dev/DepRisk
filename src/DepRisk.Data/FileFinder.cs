using System.IO.Enumeration;
using DepRisk.Core;

namespace DepRisk.Data;

/// <summary>
/// Finds files of one exact name under a directory, with bounds suitable for untrusted trees: symlinks and junctions are
/// never followed, <c>node_modules</c>, <c>.git</c>, and <c>.deprisk</c> are not entered, depth and result count are limited,
/// and the result is sorted so it never depends on file-system enumeration order.
/// </summary>
internal static class FileFinder
{
    private const int MaxResults = 5000;
    private const int MaxRecursionDepth = 32;

    private static readonly HashSet<string> SkippedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git",
        "node_modules",
        ".deprisk",
    };

    /// <returns>Full paths, sorted. A path that is an existing file is returned as is, whatever its name.</returns>
    public static IReadOnlyList<string> Find(string path, string fileName)
    {
        string fullPath = Path.GetFullPath(path);

        if (File.Exists(fullPath))
        {
            return [fullPath];
        }

        if (!Directory.Exists(fullPath))
        {
            throw new InvalidInputException($"path not found: {path}");
        }

        List<string> found = Enumerate(fullPath, fileName).Take(MaxResults + 1).ToList();

        if (found.Count > MaxResults)
        {
            throw new InvalidInputException($"too many {fileName} files under '{path}' (limit {MaxResults}).");
        }

        found.Sort(StringComparer.OrdinalIgnoreCase);
        return found;
    }

    /// <summary>Like <see cref="Find"/> for a directory, but returns an empty list instead of throwing when nothing is there; never accepts a file.</summary>
    public static IReadOnlyList<string> FindInDirectory(string directory, string fileName)
    {
        List<string> found = Enumerate(directory, fileName).Take(MaxResults + 1).ToList();

        if (found.Count > MaxResults)
        {
            throw new InvalidInputException($"too many {fileName} files under '{directory}' (limit {MaxResults}).");
        }

        found.Sort(StringComparer.OrdinalIgnoreCase);
        return found;
    }

    private static FileSystemEnumerable<string> Enumerate(string directory, string fileName)
    {
        EnumerationOptions options = new()
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            MaxRecursionDepth = MaxRecursionDepth,

            // Never follow symlinks or junctions: a hostile tree must not lead us outside the requested directory.
            AttributesToSkip = FileAttributes.ReparsePoint,
        };

        return new FileSystemEnumerable<string>(
            directory,
            static (ref FileSystemEntry entry) => entry.ToFullPath(),
            options)
        {
            ShouldIncludePredicate = (ref FileSystemEntry entry) =>
                !entry.IsDirectory && entry.FileName.Equals(fileName, StringComparison.OrdinalIgnoreCase),
            ShouldRecursePredicate = static (ref FileSystemEntry entry) =>
                !SkippedDirectories.Contains(entry.FileName.ToString()),
        };
    }
}

using System.IO.Enumeration;
using DepRisk.Core;

namespace DepRisk.Data.NuGet;

/// <summary>Finds <c>project.assets.json</c> files under a directory, with bounds suitable for untrusted trees.</summary>
public static class AssetsFileLocator
{
    public const string FileName = "project.assets.json";

    private const int MaxResults = 5000;
    private const int MaxRecursionDepth = 32;

    private static readonly HashSet<string> SkippedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git",
        "node_modules",
        ".deprisk",
    };

    /// <returns>Full paths, sorted, so results never depend on file-system enumeration order.</returns>
    public static IReadOnlyList<string> Find(string path)
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

        EnumerationOptions options = new()
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            MaxRecursionDepth = MaxRecursionDepth,

            // Never follow symlinks or junctions: a hostile tree must not lead us outside the requested directory.
            AttributesToSkip = FileAttributes.ReparsePoint,
        };

        FileSystemEnumerable<string> enumerable = new(
            fullPath,
            static (ref FileSystemEntry entry) => entry.ToFullPath(),
            options)
        {
            ShouldIncludePredicate = static (ref FileSystemEntry entry) =>
                !entry.IsDirectory && entry.FileName.Equals(FileName, StringComparison.OrdinalIgnoreCase),
            ShouldRecursePredicate = static (ref FileSystemEntry entry) =>
                !SkippedDirectories.Contains(entry.FileName.ToString()),
        };

        List<string> found = enumerable.Take(MaxResults + 1).ToList();

        if (found.Count > MaxResults)
        {
            throw new InvalidInputException($"too many {FileName} files under '{path}' (limit {MaxResults}).");
        }

        found.Sort(StringComparer.OrdinalIgnoreCase);
        return found;
    }
}

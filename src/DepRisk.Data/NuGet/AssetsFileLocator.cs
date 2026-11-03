using DepRisk.Core;

namespace DepRisk.Data.NuGet;

/// <summary>Finds <c>project.assets.json</c> files under a directory, with bounds suitable for untrusted trees (see <see cref="FileFinder"/>).</summary>
public static class AssetsFileLocator
{
    public const string FileName = "project.assets.json";

    /// <returns>Full paths, sorted, so results never depend on file-system enumeration order.</returns>
    public static IReadOnlyList<string> Find(string path) => FileFinder.Find(path, FileName);

    /// <summary>The assets files below a directory (none if there are none); never treats the argument as a file.</summary>
    internal static IReadOnlyList<string> FindIn(string directory) => FileFinder.FindInDirectory(directory, FileName);
}

namespace DepRisk.Data.NuGet;

/// <summary>Finds <c>packages.lock.json</c> files under a directory, with the same bounds as for assets files (see <see cref="FileFinder"/>).</summary>
public static class NuGetLockFileLocator
{
    public const string FileName = "packages.lock.json";

    /// <returns>Full paths, sorted, so results never depend on file-system enumeration order.</returns>
    public static IReadOnlyList<string> Find(string path) => FileFinder.Find(path, FileName);

    /// <summary>The lock files below a directory (none if there are none); never treats the argument as a file.</summary>
    internal static IReadOnlyList<string> FindIn(string directory) => FileFinder.FindInDirectory(directory, FileName);
}

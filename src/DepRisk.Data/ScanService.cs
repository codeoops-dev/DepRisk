using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.NuGet;

namespace DepRisk.Data;

/// <summary>Builds a <see cref="ScanResult"/> from the restore output found at a path.</summary>
public static class ScanService
{
    /// <summary>Upper bound for a single assets file. Real files are a few MB; anything huge is rejected.</summary>
    public const long MaxFileBytes = 128L * 1024 * 1024;

    public static ScanResult Scan(string path, ToolInfo tool)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(tool);

        string fullPath = Path.GetFullPath(path);
        IReadOnlyList<string> files = AssetsFileLocator.Find(fullPath);

        if (files.Count == 0)
        {
            throw new InvalidInputException(
                $"no {AssetsFileLocator.FileName} found under '{path}'. Run 'dotnet restore' first, or pass the path to a {AssetsFileLocator.FileName}.");
        }

        string root = Directory.Exists(fullPath) ? fullPath : Path.GetDirectoryName(fullPath) ?? fullPath;

        List<ProjectGraph> projects = files
            .Select(file => Load(file, root))
            .OrderBy(p => p.AssetsFile, StringComparer.Ordinal)
            .ToList();

        return new ScanResult(ScanResult.CurrentSchemaVersion, tool, "nuget", projects);
    }

    private static ProjectGraph Load(string file, string root)
    {
        string display = Path.GetRelativePath(root, file).Replace('\\', '/');

        string json;

        try
        {
            long length = new FileInfo(file).Length;

            if (length > MaxFileBytes)
            {
                throw new InvalidInputException($"{display}: file is too large ({length} bytes; limit {MaxFileBytes}).");
            }

            json = File.ReadAllText(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"{display}: cannot read file ({ex.Message})", ex);
        }

        // obj/project.assets.json lives two levels below the project directory.
        string? projectDirectory = Path.GetDirectoryName(Path.GetDirectoryName(file));
        string fallbackName = (projectDirectory is null ? null : Path.GetFileName(projectDirectory)) is { Length: > 0 } name
            ? name
            : "unknown";

        return NuGetAssetsParser.Parse(json, display, fallbackName);
    }
}

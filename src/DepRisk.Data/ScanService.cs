using System.Text;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.NuGet;

namespace DepRisk.Data;

/// <summary>A scan result plus the digest of everything that was read to produce it (for the audit log).</summary>
public sealed record ScanOutcome(ScanResult Result, string InputsDigest);

/// <summary>Builds a <see cref="ScanResult"/> from the restore output found at a path.</summary>
public static class ScanService
{
    /// <summary>Upper bound for a single assets file. Real files are a few MB; anything huge is rejected.</summary>
    public const long MaxFileBytes = 128L * 1024 * 1024;

    public static ScanResult Scan(string path, ToolInfo tool) => ScanDetailed(path, tool).Result;

    public static ScanOutcome ScanDetailed(string path, ToolInfo tool)
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

        List<Loaded> loaded = files
            .Select(file => Load(file, root))
            .OrderBy(l => l.Graph.AssetsFile, StringComparer.Ordinal)
            .ToList();

        // The digest covers the exact bytes of every input file, in a fixed order, tied to its relative path.
        StringBuilder inputs = new();

        foreach (Loaded item in loaded)
        {
            inputs.Append(item.FileDigest).Append("  ").Append(item.Graph.AssetsFile).Append('\n');
        }

        ScanResult result = new(ScanResult.CurrentSchemaVersion, tool, "nuget", loaded.Select(l => l.Graph).ToList());
        return new ScanOutcome(result, Digest.Sha256Hex(inputs.ToString()));
    }

    private static Loaded Load(string file, string root)
    {
        string display = Path.GetRelativePath(root, file).Replace('\\', '/');

        byte[] bytes;

        try
        {
            long length = new FileInfo(file).Length;

            if (length > MaxFileBytes)
            {
                throw new InvalidInputException($"{display}: file is too large ({length} bytes; limit {MaxFileBytes}).");
            }

            bytes = File.ReadAllBytes(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"{display}: cannot read file ({ex.Message})", ex);
        }

        string json;

        using (MemoryStream stream = new(bytes))
        using (StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
        {
            json = reader.ReadToEnd();
        }

        // obj/project.assets.json lives two levels below the project directory.
        string? projectDirectory = Path.GetDirectoryName(Path.GetDirectoryName(file));
        string fallbackName = (projectDirectory is null ? null : Path.GetFileName(projectDirectory)) is { Length: > 0 } name
            ? name
            : "unknown";

        return new Loaded(NuGetAssetsParser.Parse(json, display, fallbackName), Digest.Sha256Hex(bytes));
    }

    private sealed record Loaded(ProjectGraph Graph, string FileDigest);
}

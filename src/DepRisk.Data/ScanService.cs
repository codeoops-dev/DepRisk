using System.Text;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.NuGet;
using DepRisk.Data.Npm;

namespace DepRisk.Data;

/// <summary>A scan result plus the digest of everything that was read to produce it (for the audit log).</summary>
public sealed record ScanOutcome(ScanResult Result, string InputsDigest);

/// <summary>
/// Builds a <see cref="ScanResult"/> from the dependency files found at a path: NuGet <c>project.assets.json</c> (written by
/// <c>dotnet restore</c>) or npm <c>package-lock.json</c>. One scan reads one ecosystem; when it is not named, it is detected
/// from the files found, and a tree that has both is an error that asks the caller to choose (ADR 0010).
/// </summary>
public static class ScanService
{
    /// <summary>Upper bound for a single assets or lock file. Real files are a few MB; anything huge is rejected.</summary>
    public const long MaxFileBytes = 128L * 1024 * 1024;

    public static ScanResult Scan(string path, ToolInfo tool, Ecosystem? ecosystem = null) => ScanDetailed(path, tool, ecosystem).Result;

    /// <param name="ecosystem">The ecosystem to read; null detects it from the files found.</param>
    public static ScanOutcome ScanDetailed(string path, ToolInfo tool, Ecosystem? ecosystem = null)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(tool);

        string fullPath = Path.GetFullPath(path);
        (Ecosystem resolved, IReadOnlyList<string> files) = Locate(path, fullPath, ecosystem);

        string root = Directory.Exists(fullPath) ? fullPath : Path.GetDirectoryName(fullPath) ?? fullPath;

        List<Loaded> loaded = files
            .Select(file => Load(file, root, resolved))
            .OrderBy(l => l.Graph.AssetsFile, StringComparer.Ordinal)
            .ToList();

        // The digest covers the exact bytes of every input file, in a fixed order, tied to its relative path.
        StringBuilder inputs = new();

        foreach (Loaded item in loaded)
        {
            inputs.Append(item.FileDigest).Append("  ").Append(item.Graph.AssetsFile).Append('\n');
        }

        ScanResult result = new(ScanResult.CurrentSchemaVersion, tool, resolved.Id, loaded.Select(l => l.Graph).ToList());
        return new ScanOutcome(result, Digest.Sha256Hex(inputs.ToString()));
    }

    /// <summary>Decides the ecosystem and the files to read. Throws <see cref="InvalidInputException"/> with a hint when there is nothing to read.</summary>
    private static (Ecosystem Ecosystem, IReadOnlyList<string> Files) Locate(string displayPath, string fullPath, Ecosystem? requested)
    {
        if (requested is not null)
        {
            IReadOnlyList<string> found = requested == Ecosystem.Npm ? NpmLockFileLocator.Find(fullPath) : AssetsFileLocator.Find(fullPath);

            if (found.Count == 0)
            {
                throw new InvalidInputException(NothingFoundMessage(displayPath, requested));
            }

            return (requested, found);
        }

        if (File.Exists(fullPath))
        {
            string name = Path.GetFileName(fullPath);

            if (name.Equals(AssetsFileLocator.FileName, StringComparison.OrdinalIgnoreCase))
            {
                return (Ecosystem.NuGet, [fullPath]);
            }

            if (name.Equals(NpmLockFileLocator.FileName, StringComparison.OrdinalIgnoreCase))
            {
                return (Ecosystem.Npm, [fullPath]);
            }

            throw new InvalidInputException(
                $"'{displayPath}' is not a dependency file DepRisk recognizes by name (expected {AssetsFileLocator.FileName} for NuGet or "
                + $"{NpmLockFileLocator.FileName} for npm). If it has another name, say what it is with --ecosystem nuget|npm.");
        }

        if (!Directory.Exists(fullPath))
        {
            throw new InvalidInputException($"path not found: {displayPath}");
        }

        IReadOnlyList<string> nuget = AssetsFileLocator.FindIn(fullPath);
        IReadOnlyList<string> npm = NpmLockFileLocator.FindIn(fullPath);

        if (nuget.Count > 0 && npm.Count > 0)
        {
            throw new InvalidInputException(
                $"'{displayPath}' has both NuGet ({nuget.Count} {AssetsFileLocator.FileName}) and npm ({npm.Count} {NpmLockFileLocator.FileName}) dependency files. "
                + "Choose one with --ecosystem nuget or --ecosystem npm.");
        }

        if (nuget.Count > 0)
        {
            return (Ecosystem.NuGet, nuget);
        }

        if (npm.Count > 0)
        {
            return (Ecosystem.Npm, npm);
        }

        throw new InvalidInputException(
            $"no {AssetsFileLocator.FileName} (NuGet) or {NpmLockFileLocator.FileName} (npm) found under '{displayPath}'. "
            + "Run 'dotnet restore' or 'npm install' first, or pass the path to the file.");
    }

    private static string NothingFoundMessage(string displayPath, Ecosystem ecosystem) =>
        ecosystem == Ecosystem.Npm
            ? $"no {NpmLockFileLocator.FileName} found under '{displayPath}'. Run 'npm install' (or 'npm install --package-lock-only') first, or pass the path to a {NpmLockFileLocator.FileName}."
            : $"no {AssetsFileLocator.FileName} found under '{displayPath}'. Run 'dotnet restore' first, or pass the path to a {AssetsFileLocator.FileName}.";

    private static Loaded Load(string file, string root, Ecosystem ecosystem)
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

        string fileDirectory = Path.GetDirectoryName(file) ?? string.Empty;

        if (ecosystem == Ecosystem.Npm)
        {
            // package-lock.json lives in the project directory, next to package.json.
            string npmFallback = Path.GetFileName(fileDirectory) is { Length: > 0 } npmName ? npmName : "unknown";
            ProjectGraph npm = NpmLockParser.Parse(json, display, npmFallback);

            string directoryPart = display.Contains('/', StringComparison.Ordinal) ? display[..(display.LastIndexOf('/') + 1)] : string.Empty;
            string? packageJson = File.Exists(Path.Combine(fileDirectory, "package.json")) ? directoryPart + "package.json" : null;
            return new Loaded(npm with { ProjectFile = packageJson }, Digest.Sha256Hex(bytes));
        }

        // obj/project.assets.json lives two levels below the project directory.
        string? projectDirectory = Path.GetDirectoryName(Path.GetDirectoryName(file));
        string fallbackName = (projectDirectory is null ? null : Path.GetFileName(projectDirectory)) is { Length: > 0 } name
            ? name
            : "unknown";

        ProjectGraph parsed = NuGetAssetsParser.Parse(json, display, fallbackName);
        return new Loaded(parsed with { ProjectFile = ComposeProjectFile(display, parsed.ProjectFile) }, Digest.Sha256Hex(bytes));
    }

    /// <summary>
    /// "src/App/obj/project.assets.json" and the file name "App.csproj" give "src/App/App.csproj".
    /// Returns null when the assets file is not in an "obj" directory below the scanned root.
    /// </summary>
    public static string? ComposeProjectFile(string assetsDisplayPath, string? projectFileName)
    {
        if (projectFileName is null)
        {
            return null;
        }

        const string suffix = "obj/" + AssetsFileLocator.FileName;

        if (assetsDisplayPath.Equals(suffix, StringComparison.Ordinal))
        {
            return projectFileName;
        }

        return assetsDisplayPath.EndsWith("/" + suffix, StringComparison.Ordinal)
            ? assetsDisplayPath[..^suffix.Length] + projectFileName
            : null;
    }

    private sealed record Loaded(ProjectGraph Graph, string FileDigest);
}

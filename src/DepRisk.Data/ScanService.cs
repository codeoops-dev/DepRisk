using System.Text;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.NuGet;
using DepRisk.Data.Npm;
using DepRisk.Data.Sbom;

namespace DepRisk.Data;

/// <summary>
/// A scan result plus the digest of everything that was read to produce it (for the audit log). <c>IsSbom</c> says the graph was read
/// from an SBOM: it has no version ranges and no install paths (ADR 0029).
/// </summary>
public sealed record ScanOutcome(ScanResult Result, string InputsDigest, bool IsSbom = false);

/// <summary>
/// Builds a <see cref="ScanResult"/> from the dependency files found at a path: NuGet <c>project.assets.json</c> (written by
/// <c>dotnet restore</c>) or <c>packages.lock.json</c>, or npm <c>package-lock.json</c>. One scan reads one ecosystem; when it is
/// not named, it is detected from the files found, and a tree that has both is an error that asks the caller to choose (ADR 0010).
/// For a NuGet project that has both an assets file (in its <c>obj</c> directory) and a lock file, the assets file is read and the
/// lock file is not, so one project is never counted twice (ADR 0027). A path to one file can also be a CycloneDX or SPDX SBOM
/// (ADR 0029): never found by searching a directory, only by being named.
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

        if (File.Exists(fullPath) && IsSbomFile(fullPath, ecosystem))
        {
            return ScanSbom(fullPath, tool, ecosystem);
        }

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

            // Another file the graph was read together with (the package.json beside an npm lockfileVersion 1 file).
            foreach ((string digest, string name) in item.ExtraInputs)
            {
                inputs.Append(digest).Append("  ").Append(name).Append('\n');
            }
        }

        ScanResult result = new(ScanResult.CurrentSchemaVersion, tool, resolved.Id, loaded.Select(l => l.Graph).ToList());
        return new ScanOutcome(result, Digest.Sha256Hex(inputs.ToString()));
    }

    /// <summary>
    /// A file is read as an SBOM when its name says so (bom.json, sbom.json, *.cdx.json, *.spdx.json), or when the ecosystem is named
    /// and the file, whatever it is called, is not one of the lock or assets files and is a CycloneDX or SPDX document.
    /// </summary>
    private static bool IsSbomFile(string fullPath, Ecosystem? requested)
    {
        string name = Path.GetFileName(fullPath);

        if (SbomParser.IsSbomFileName(name))
        {
            return true;
        }

        if (requested is null
            || name.Equals(AssetsFileLocator.FileName, StringComparison.OrdinalIgnoreCase)
            || name.Equals(NuGetLockFileLocator.FileName, StringComparison.OrdinalIgnoreCase)
            || name.Equals(NpmLockFileLocator.FileName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return SbomParser.LooksLikeSbom(DecodeText(ReadBounded(fullPath, name)));
    }

    private static ScanOutcome ScanSbom(string fullPath, ToolInfo tool, Ecosystem? requested)
    {
        string root = Path.GetDirectoryName(fullPath) ?? fullPath;
        string display = Path.GetRelativePath(root, fullPath).Replace('\\', '/');

        byte[] bytes = ReadBounded(fullPath, display);
        string fallbackName = Path.GetFileNameWithoutExtension(display);

        (Ecosystem ecosystem, ProjectGraph graph) = SbomParser.Parse(DecodeText(bytes), display, fallbackName, requested);

        ScanResult result = new(ScanResult.CurrentSchemaVersion, tool, ecosystem.Id, [graph]);
        string inputs = Digest.Sha256Hex(bytes) + "  " + display + "\n";

        return new ScanOutcome(result, Digest.Sha256Hex(inputs), IsSbom: true);
    }

    /// <summary>Decides the ecosystem and the files to read. Throws <see cref="InvalidInputException"/> with a hint when there is nothing to read.</summary>
    private static (Ecosystem Ecosystem, IReadOnlyList<string> Files) Locate(string displayPath, string fullPath, Ecosystem? requested)
    {
        if (requested is not null)
        {
            IReadOnlyList<string> found = requested == Ecosystem.Npm ? NpmLockFileLocator.Find(fullPath) : FindNuGet(fullPath);

            if (found.Count == 0)
            {
                throw new InvalidInputException(NothingFoundMessage(displayPath, requested));
            }

            return (requested, found);
        }

        if (File.Exists(fullPath))
        {
            string name = Path.GetFileName(fullPath);

            if (name.Equals(AssetsFileLocator.FileName, StringComparison.OrdinalIgnoreCase)
                || name.Equals(NuGetLockFileLocator.FileName, StringComparison.OrdinalIgnoreCase))
            {
                return (Ecosystem.NuGet, [fullPath]);
            }

            if (name.Equals(NpmLockFileLocator.FileName, StringComparison.OrdinalIgnoreCase))
            {
                return (Ecosystem.Npm, [fullPath]);
            }

            throw new InvalidInputException(
                $"'{displayPath}' is not a dependency file DepRisk recognizes by name (expected {AssetsFileLocator.FileName} or {NuGetLockFileLocator.FileName} "
                + $"for NuGet, {NpmLockFileLocator.FileName} for npm, or bom.json, sbom.json, *.cdx.json or *.spdx.json for an SBOM). If it has another name, say what it is with --ecosystem nuget|npm.");
        }

        if (!Directory.Exists(fullPath))
        {
            throw new InvalidInputException($"path not found: {displayPath}");
        }

        IReadOnlyList<string> nuget = MergeNuGet(AssetsFileLocator.FindIn(fullPath), NuGetLockFileLocator.FindIn(fullPath));
        IReadOnlyList<string> npm = NpmLockFileLocator.FindIn(fullPath);

        if (nuget.Count > 0 && npm.Count > 0)
        {
            throw new InvalidInputException(
                $"'{displayPath}' has both NuGet ({DescribeNuGet(nuget)}) and npm ({npm.Count} {NpmLockFileLocator.FileName}) dependency files. "
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
            $"no {AssetsFileLocator.FileName} or {NuGetLockFileLocator.FileName} (NuGet) or {NpmLockFileLocator.FileName} (npm) found under '{displayPath}'. "
            + "Run 'dotnet restore' or 'npm install' first, or pass the path to the file (a CycloneDX or SPDX SBOM is read only when its path is given).");
    }

    /// <summary>
    /// The NuGet files for a path: the path itself when it is a file, else the assets files and the lock files below a directory.
    /// A path that does not exist is the same input error as before (the assets locator reports it).
    /// </summary>
    private static IReadOnlyList<string> FindNuGet(string fullPath) =>
        Directory.Exists(fullPath)
            ? MergeNuGet(AssetsFileLocator.FindIn(fullPath), NuGetLockFileLocator.FindIn(fullPath))
            : AssetsFileLocator.Find(fullPath);

    /// <summary>
    /// A project that has an assets file in its <c>obj</c> directory is read from that file; its <c>packages.lock.json</c> (in the
    /// project directory, above <c>obj</c>) is then not read, because both describe the same restore. A lock file without an assets
    /// file next to it (a fresh checkout that has not restored) is read on its own.
    /// </summary>
    private static IReadOnlyList<string> MergeNuGet(IReadOnlyList<string> assets, IReadOnlyList<string> locks)
    {
        if (locks.Count == 0)
        {
            return assets;
        }

        HashSet<string> covered = new(StringComparer.OrdinalIgnoreCase);

        foreach (string assetsFile in assets)
        {
            string? objDirectory = Path.GetDirectoryName(assetsFile);

            if (objDirectory is not null
                && Path.GetFileName(objDirectory).Equals("obj", StringComparison.OrdinalIgnoreCase)
                && Path.GetDirectoryName(objDirectory) is { } projectDirectory)
            {
                covered.Add(projectDirectory);
            }
        }

        List<string> merged = [.. assets, .. locks.Where(file => !covered.Contains(Path.GetDirectoryName(file) ?? string.Empty))];
        merged.Sort(StringComparer.OrdinalIgnoreCase);
        return merged;
    }

    /// <summary>"1 project.assets.json" or "2 project.assets.json, 1 packages.lock.json": what was found, by kind.</summary>
    private static string DescribeNuGet(IReadOnlyList<string> files)
    {
        int locks = files.Count(file => Path.GetFileName(file).Equals(NuGetLockFileLocator.FileName, StringComparison.OrdinalIgnoreCase));
        int assets = files.Count - locks;

        List<string> parts = [];

        if (assets > 0)
        {
            parts.Add($"{assets} {AssetsFileLocator.FileName}");
        }

        if (locks > 0)
        {
            parts.Add($"{locks} {NuGetLockFileLocator.FileName}");
        }

        return string.Join(", ", parts);
    }

    private static string NothingFoundMessage(string displayPath, Ecosystem ecosystem) =>
        ecosystem == Ecosystem.Npm
            ? $"no {NpmLockFileLocator.FileName} found under '{displayPath}'. Run 'npm install' (or 'npm install --package-lock-only') first, or pass the path to a {NpmLockFileLocator.FileName}."
            : $"no {AssetsFileLocator.FileName} or {NuGetLockFileLocator.FileName} found under '{displayPath}'. Run 'dotnet restore' first "
              + $"(a {NuGetLockFileLocator.FileName} is written when the project uses lock files), or pass the path to one of these files.";

    private static Loaded Load(string file, string root, Ecosystem ecosystem)
    {
        string display = Path.GetRelativePath(root, file).Replace('\\', '/');

        byte[] bytes = ReadBounded(file, display);
        string json = DecodeText(bytes);
        string fileDirectory = Path.GetDirectoryName(file) ?? string.Empty;
        string directoryPart = display.Contains('/', StringComparison.Ordinal) ? display[..(display.LastIndexOf('/') + 1)] : string.Empty;

        if (ecosystem == Ecosystem.Npm)
        {
            // package-lock.json lives in the project directory, next to package.json.
            string npmFallback = Path.GetFileName(fileDirectory) is { Length: > 0 } npmName ? npmName : "unknown";
            string manifestPath = Path.Combine(fileDirectory, "package.json");
            string manifestDisplay = directoryPart + "package.json";
            byte[]? manifestBytes = null;

            // Only lockfileVersion 1 asks for the package.json (it does not record what the project asks for); the others never read it.
            ProjectGraph npm = NpmLockParser.Parse(json, display, npmFallback, () =>
            {
                manifestBytes = ReadManifest(manifestPath, manifestDisplay);
                return manifestBytes is null ? null : DecodeText(manifestBytes);
            });

            string? packageJson = File.Exists(manifestPath) ? manifestDisplay : null;
            List<(string Digest, string Name)> extra = manifestBytes is null ? [] : [(Digest.Sha256Hex(manifestBytes), manifestDisplay)];
            return new Loaded(npm with { ProjectFile = packageJson }, Digest.Sha256Hex(bytes), extra);
        }

        if (Path.GetFileName(file).Equals(NuGetLockFileLocator.FileName, StringComparison.OrdinalIgnoreCase))
        {
            // packages.lock.json lives in the project directory, next to the project file. It records neither the project's name nor
            // its path: both come from the project file next to it when there is exactly one, else from the directory.
            string? projectFileName = SingleProjectFileIn(fileDirectory);
            string lockName = projectFileName is not null
                ? Path.GetFileNameWithoutExtension(projectFileName)
                : Path.GetFileName(fileDirectory) is { Length: > 0 } lockDirectoryName ? lockDirectoryName : "unknown";

            ProjectGraph lockGraph = NuGetLockParser.Parse(json, display, lockName);
            return new Loaded(lockGraph with { ProjectFile = projectFileName is null ? null : directoryPart + projectFileName }, Digest.Sha256Hex(bytes), []);
        }

        // obj/project.assets.json lives two levels below the project directory.
        string? projectDirectory = Path.GetDirectoryName(Path.GetDirectoryName(file));
        string fallbackName = (projectDirectory is null ? null : Path.GetFileName(projectDirectory)) is { Length: > 0 } name
            ? name
            : "unknown";

        ProjectGraph parsed = NuGetAssetsParser.Parse(json, display, fallbackName);
        return new Loaded(parsed with { ProjectFile = ComposeProjectFile(display, parsed.ProjectFile) }, Digest.Sha256Hex(bytes), []);
    }

    private static byte[] ReadBounded(string file, string display)
    {
        try
        {
            long length = new FileInfo(file).Length;

            if (length > MaxFileBytes)
            {
                throw new InvalidInputException($"{display}: file is too large ({length} bytes; limit {MaxFileBytes}).");
            }

            return File.ReadAllBytes(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"{display}: cannot read file ({ex.Message})", ex);
        }
    }

    private static string DecodeText(byte[] bytes)
    {
        using MemoryStream stream = new(bytes);
        using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    /// <summary>
    /// The <c>package.json</c> beside a lock file, or null if there is none. A link is not followed: a scanned tree must not make
    /// DepRisk read a file outside it (the same rule as for finding the dependency files).
    /// </summary>
    private static byte[]? ReadManifest(string path, string display)
    {
        FileInfo info = new(path);

        if (!info.Exists)
        {
            return null;
        }

        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint) || info.LinkTarget is not null)
        {
            throw new InvalidInputException($"{display}: is a link, and DepRisk does not follow links in a scanned tree.");
        }

        return ReadBounded(path, display);
    }

    /// <summary>The file name of the one <c>.csproj</c>, <c>.fsproj</c> or <c>.vbproj</c> in a directory; null when there is none or several.</summary>
    private static string? SingleProjectFileIn(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return null;
        }

        EnumerationOptions options = new() { IgnoreInaccessible = true, RecurseSubdirectories = false, AttributesToSkip = FileAttributes.ReparsePoint };

        List<string> projects = Directory.EnumerateFiles(directory, "*", options)
            .Select(path => Path.GetFileName(path))
            .Where(name => name.Length <= 255
                && !name.Any(char.IsControl)
                && (name.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                    || name.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase)
                    || name.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase)))
            .Take(2)
            .ToList();

        return projects.Count == 1 ? projects[0] : null;
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

    private sealed record Loaded(ProjectGraph Graph, string FileDigest, IReadOnlyList<(string Digest, string Name)> ExtraInputs);
}

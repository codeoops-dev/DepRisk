using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;

namespace DepRisk.Data.NuGet;

/// <summary>
/// Reads the resolved dependency graph from a NuGet <c>packages.lock.json</c> (written by <c>dotnet restore --use-lock-file</c>, or
/// when the project sets <c>RestorePackagesWithLockFile</c>). The input is untrusted: the parser is bounded (JSON depth), never
/// executes anything, validates every name that ends up in a result, and reports problems as <see cref="InvalidInputException"/>.
/// See ADR 0027.
/// </summary>
/// <remarks>
/// Supported format versions (the shapes follow NuGet.Client, <c>PackagesLockFileFormat</c>):
/// <list type="bullet">
/// <item>1 and 2: a <c>dependencies</c> object keyed by target (<c>net8.0</c>, or <c>net8.0/win-x64</c>); each value maps a package id to an
/// entry. Version 2 only adds the <c>CentralTransitive</c> type (a package pinned by central package management).</item>
/// <item>3: the targets sit at the top level of the file, keyed by the target framework <em>alias</em> (optionally followed by
/// <c>/</c> and a runtime identifier), and each holds <c>framework</c> and <c>dependencies</c>. DepRisk uses the key as the target
/// name, like for version 4 of the assets file.</item>
/// </list>
/// Entry types: <c>Direct</c> (the project asks for it: direct, with its <c>requested</c> range), <c>Transitive</c> and
/// <c>CentralTransitive</c> (installed, not asked for by the project), and <c>Project</c> (a project-to-project reference: not a
/// package, no advisories). A missing or unknown <c>type</c> is an error, not a guess. A lock file has no project name or path:
/// the caller supplies them from the directory (see <c>ScanService</c>).
/// </remarks>
public static class NuGetLockParser
{
    private const int MaxIdLength = 256;
    private const int MaxVersionLength = 256;
    private const int MaxRangeLength = 1000;
    private const int MaxRequestedLength = 200;
    private const int MaxTargetNameLength = 200;

    private static readonly int[] SupportedLockVersions = [1, 2, 3];

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 64,
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
    };

    public static ProjectGraph Parse(string json, string displayPath, string projectName)
    {
        ArgumentNullException.ThrowIfNull(json);
        ArgumentNullException.ThrowIfNull(projectName);

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(json, DocumentOptions);
        }
        catch (JsonException ex)
        {
            throw new InvalidInputException($"{displayPath}: not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("version", out JsonElement versionElement)
                || versionElement.ValueKind != JsonValueKind.Number
                || !versionElement.TryGetInt32(out int version))
            {
                throw new InvalidInputException($"{displayPath}: not a NuGet packages lock file (missing 'version').");
            }

            if (!SupportedLockVersions.Contains(version))
            {
                throw new InvalidInputException(
                    $"{displayPath}: unsupported packages lock file version {version} (supported: {string.Join(", ", SupportedLockVersions)}). "
                    + $"Please report your .NET SDK version at {ProductInfo.RepositoryUrl}/issues.");
            }

            List<TargetGraph> targets = version >= 3 ? ReadAliasedTargets(root, displayPath) : ReadTargets(root, displayPath);

            // A lock file always has one target per framework of the project. None means this reader does not understand the
            // file, and "no packages" must never be the quiet answer to that.
            if (targets.Count == 0)
            {
                throw new InvalidInputException($"{displayPath}: the lock file has no targets.");
            }

            return new ProjectGraph(projectName, displayPath, targets.OrderBy(t => t.Name, StringComparer.Ordinal).ToList());
        }
    }

    /// <summary>Versions 1 and 2: <c>dependencies</c> maps a target to its entries.</summary>
    private static List<TargetGraph> ReadTargets(JsonElement root, string displayPath)
    {
        if (!root.TryGetProperty("dependencies", out JsonElement dependencies) || dependencies.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidInputException($"{displayPath}: the lock file has no 'dependencies' object.");
        }

        List<TargetGraph> targets = [];
        HashSet<string> names = new(StringComparer.Ordinal);

        foreach (JsonProperty target in dependencies.EnumerateObject())
        {
            RequireTargetName(target.Name, displayPath, names);

            if (target.Value.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidInputException($"{displayPath}: the target '{SafeText.Clean(target.Name, 100)}' is not an object.");
            }

            targets.Add(ReadTarget(target.Name, target.Value, displayPath));
        }

        return targets;
    }

    /// <summary>
    /// Version 3: every top-level property other than <c>version</c> that is an object with a <c>framework</c> is a target (this is
    /// how NuGet itself reads the file; anything else is not a target and is ignored).
    /// </summary>
    private static List<TargetGraph> ReadAliasedTargets(JsonElement root, string displayPath)
    {
        List<TargetGraph> targets = [];
        HashSet<string> names = new(StringComparer.Ordinal);

        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (property.Name == "version"
                || property.Value.ValueKind != JsonValueKind.Object
                || !property.Value.TryGetProperty("framework", out JsonElement framework)
                || framework.ValueKind != JsonValueKind.String
                || string.IsNullOrEmpty(framework.GetString()))
            {
                continue;
            }

            RequireTargetName(property.Name, displayPath, names);

            bool hasEntries = property.Value.TryGetProperty("dependencies", out JsonElement entries);

            if (hasEntries && entries.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidInputException($"{displayPath}: the 'dependencies' of the target '{SafeText.Clean(property.Name, 100)}' is not an object.");
            }

            targets.Add(hasEntries ? ReadTarget(property.Name, entries, displayPath) : new TargetGraph(property.Name, []));
        }

        return targets;
    }

    private static void RequireTargetName(string name, string displayPath, HashSet<string> seen)
    {
        if (name.Length is 0 or > MaxTargetNameLength || name.Any(char.IsControl))
        {
            throw new InvalidInputException($"{displayPath}: invalid target name '{SafeText.Clean(name, 100)}'.");
        }

        if (!seen.Add(name))
        {
            throw new InvalidInputException($"{displayPath}: duplicate target '{SafeText.Clean(name, 100)}'.");
        }
    }

    private static TargetGraph ReadTarget(string targetName, JsonElement entries, string displayPath)
    {
        List<ResolvedPackage> packages = [];
        HashSet<string> ids = new(StringComparer.OrdinalIgnoreCase);

        foreach (JsonProperty entry in entries.EnumerateObject())
        {
            // NuGet ids are not case sensitive: two entries that differ only in case would silently shadow each other later.
            if (!ids.Add(entry.Name))
            {
                throw new InvalidInputException($"{displayPath}: duplicate package '{SafeText.Clean(entry.Name, 100)}' in the target '{SafeText.Clean(targetName, 100)}'.");
            }

            ResolvedPackage? package = ReadPackage(entry, displayPath);

            if (package is not null)
            {
                packages.Add(package);
            }
        }

        return new TargetGraph(
            targetName,
            packages
                .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.Version, StringComparer.OrdinalIgnoreCase)
                .ToList());
    }

    private static ResolvedPackage? ReadPackage(JsonProperty entry, string displayPath)
    {
        string label = SafeText.Clean(entry.Name, 100);

        if (entry.Value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidInputException($"{displayPath}: the entry '{label}' is not an object.");
        }

        RequireId(entry.Name, entry.Name, displayPath);

        if (!entry.Value.TryGetProperty("type", out JsonElement typeElement)
            || typeElement.ValueKind != JsonValueKind.String
            || typeElement.GetString() is not { } type)
        {
            throw new InvalidInputException($"{displayPath}: the entry '{label}' has no 'type'.");
        }

        bool isDirect;

        if (type.Equals("Direct", StringComparison.OrdinalIgnoreCase))
        {
            isDirect = true;
        }
        else if (type.Equals("Transitive", StringComparison.OrdinalIgnoreCase) || type.Equals("CentralTransitive", StringComparison.OrdinalIgnoreCase))
        {
            isDirect = false;
        }
        else if (type.Equals("Project", StringComparison.OrdinalIgnoreCase))
        {
            // A project-to-project reference is not a package and has no advisories.
            return null;
        }
        else
        {
            throw new InvalidInputException($"{displayPath}: the entry '{label}' has the unknown type '{SafeText.Clean(type, 40)}'.");
        }

        if (!entry.Value.TryGetProperty("resolved", out JsonElement resolvedElement)
            || resolvedElement.ValueKind != JsonValueKind.String
            || resolvedElement.GetString() is not { Length: > 0 and <= MaxVersionLength } resolved
            || resolved.Any(char.IsControl))
        {
            throw new InvalidInputException($"{displayPath}: the entry '{label}' has no valid 'resolved' version.");
        }

        string? requested = null;

        if (isDirect
            && entry.Value.TryGetProperty("requested", out JsonElement requestedElement)
            && requestedElement.ValueKind == JsonValueKind.String
            && requestedElement.GetString() is { Length: > 0 and <= MaxRequestedLength } text
            && !text.Any(char.IsControl))
        {
            requested = UrlCredentials.Mask(text);
        }

        return new ResolvedPackage(entry.Name, UrlCredentials.Mask(resolved), isDirect, ReadDependencies(entry, displayPath), requested);
    }

    private static List<DependencyRef> ReadDependencies(JsonProperty entry, string displayPath)
    {
        List<DependencyRef> dependencies = [];

        if (!entry.Value.TryGetProperty("dependencies", out JsonElement element))
        {
            return dependencies;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidInputException($"{displayPath}: the 'dependencies' of '{SafeText.Clean(entry.Name, 100)}' is not an object.");
        }

        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (JsonProperty dependency in element.EnumerateObject())
        {
            RequireId(dependency.Name, entry.Name, displayPath);

            if (!seen.Add(dependency.Name))
            {
                throw new InvalidInputException($"{displayPath}: '{SafeText.Clean(entry.Name, 100)}' lists the dependency '{SafeText.Clean(dependency.Name, 100)}' twice.");
            }

            string range = dependency.Value.ValueKind == JsonValueKind.String ? dependency.Value.GetString() ?? string.Empty : string.Empty;

            if (range.Length > MaxRangeLength || range.Any(char.IsControl))
            {
                throw new InvalidInputException(
                    $"{displayPath}: '{SafeText.Clean(entry.Name, 100)}' has an invalid version range for '{SafeText.Clean(dependency.Name, 100)}'.");
            }

            dependencies.Add(new DependencyRef(dependency.Name, UrlCredentials.Mask(range)));
        }

        return dependencies.OrderBy(d => d.Id, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static void RequireId(string id, string owner, string displayPath)
    {
        if (id.Length is 0 or > MaxIdLength || id.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '/' or '\\'))
        {
            throw new InvalidInputException($"{displayPath}: '{SafeText.Clean(owner, 100)}' contains the invalid package id '{SafeText.Clean(id, 100)}'.");
        }
    }
}

using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;

namespace DepRisk.Data.NuGet;

/// <summary>
/// Reads the resolved dependency graph from a NuGet <c>project.assets.json</c> (written by <c>dotnet restore</c>).
/// The input is untrusted: the parser is bounded (depth), never executes anything, and reports problems
/// as <see cref="InvalidInputException"/>.
/// </summary>
/// <remarks>
/// Supported format versions:
/// <list type="bullet">
/// <item>3: written by .NET SDKs older than 10.0.300 and by classic projects.</item>
/// <item>4: written by .NET SDK 10.0.300 and newer. Sections that were keyed by target framework
/// ("targets", "projectFileDependencyGroups") are keyed by the target framework <em>alias</em>
/// (usually identical to the framework name). DepRisk uses that key as-is, so both versions read the same way.</item>
/// </list>
/// Any other version is rejected: a security tool must not guess at the meaning of data it does not understand.
/// </remarks>
public static class NuGetAssetsParser
{
    private static readonly int[] SupportedAssetsVersions = [3, 4];

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 64,
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
    };

    public static ProjectGraph Parse(string json, string displayPath, string fallbackProjectName)
    {
        ArgumentNullException.ThrowIfNull(json);

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
                throw new InvalidInputException($"{displayPath}: not a NuGet assets file (missing 'version').");
            }

            if (!SupportedAssetsVersions.Contains(version))
            {
                throw new InvalidInputException(
                    $"{displayPath}: unsupported assets file version {version} (supported: {string.Join(", ", SupportedAssetsVersions)}). "
                    + $"Please report your .NET SDK version at {ProductInfo.RepositoryUrl}/issues.");
            }

            Dictionary<string, HashSet<string>> directByFramework = ReadDirectDependencies(root);
            string projectName = ReadProjectName(root) ?? fallbackProjectName;
            List<TargetGraph> targets = ReadTargets(root, directByFramework, displayPath);

            return new ProjectGraph(projectName, displayPath, targets);
        }
    }

    private static string? ReadProjectName(JsonElement root)
    {
        if (root.TryGetProperty("project", out JsonElement project)
            && project.ValueKind == JsonValueKind.Object
            && project.TryGetProperty("restore", out JsonElement restore)
            && restore.ValueKind == JsonValueKind.Object
            && restore.TryGetProperty("projectName", out JsonElement name)
            && name.ValueKind == JsonValueKind.String)
        {
            string? value = name.GetString();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        return null;
    }

    /// <summary>
    /// "projectFileDependencyGroups" lists what the project itself references, as "Id &gt;= version" strings per framework.
    /// </summary>
    private static Dictionary<string, HashSet<string>> ReadDirectDependencies(JsonElement root)
    {
        Dictionary<string, HashSet<string>> result = new(StringComparer.OrdinalIgnoreCase);

        if (!root.TryGetProperty("projectFileDependencyGroups", out JsonElement groups)
            || groups.ValueKind != JsonValueKind.Object)
        {
            return result;
        }

        foreach (JsonProperty group in groups.EnumerateObject())
        {
            HashSet<string> ids = new(StringComparer.OrdinalIgnoreCase);

            if (group.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in group.Value.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.String)
                    {
                        continue;
                    }

                    string text = item.GetString() ?? string.Empty;
                    int space = text.IndexOf(' ', StringComparison.Ordinal);
                    string id = (space > 0 ? text[..space] : text).Trim();

                    if (id.Length > 0)
                    {
                        ids.Add(id);
                    }
                }
            }

            result[group.Name] = ids;
        }

        return result;
    }

    private static List<TargetGraph> ReadTargets(
        JsonElement root,
        Dictionary<string, HashSet<string>> directByFramework,
        string displayPath)
    {
        List<TargetGraph> targets = [];

        if (!root.TryGetProperty("targets", out JsonElement targetsElement)
            || targetsElement.ValueKind != JsonValueKind.Object)
        {
            return targets;
        }

        foreach (JsonProperty target in targetsElement.EnumerateObject())
        {
            // Target names look like "net10.0" or "net10.0/win-x64" (version 4 files use the framework alias instead of the
            // framework name); direct dependencies are keyed by the part before the runtime identifier.
            int slash = target.Name.IndexOf('/', StringComparison.Ordinal);
            string framework = slash > 0 ? target.Name[..slash] : target.Name;
            directByFramework.TryGetValue(framework, out HashSet<string>? direct);

            List<ResolvedPackage> packages = [];

            if (target.Value.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty entry in target.Value.EnumerateObject())
                {
                    ResolvedPackage? package = ReadPackage(entry, direct, displayPath);

                    if (package is not null)
                    {
                        packages.Add(package);
                    }
                }
            }

            packages = packages
                .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.Version, StringComparer.OrdinalIgnoreCase)
                .ToList();

            targets.Add(new TargetGraph(target.Name, packages));
        }

        return targets.OrderBy(t => t.Name, StringComparer.Ordinal).ToList();
    }

    private static ResolvedPackage? ReadPackage(JsonProperty entry, HashSet<string>? direct, string displayPath)
    {
        // Package entries are objects. Anything else (for example bookkeeping values a newer NuGet may add) is not a package.
        if (entry.Value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        string type = "package";

        if (entry.Value.TryGetProperty("type", out JsonElement typeElement) && typeElement.ValueKind == JsonValueKind.String)
        {
            type = typeElement.GetString() ?? "package";
        }

        // Project-to-project references ("type": "project") are not packages and have no advisories.
        if (!string.Equals(type, "package", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        int slash = entry.Name.IndexOf('/', StringComparison.Ordinal);

        if (slash <= 0 || slash == entry.Name.Length - 1)
        {
            throw new InvalidInputException($"{displayPath}: unexpected package key '{entry.Name}' (expected 'Id/Version').");
        }

        string id = entry.Name[..slash];
        string packageVersion = entry.Name[(slash + 1)..];

        List<DependencyRef> dependencies = [];

        if (entry.Value.TryGetProperty("dependencies", out JsonElement dependenciesElement)
            && dependenciesElement.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty dependency in dependenciesElement.EnumerateObject())
            {
                string range = dependency.Value.ValueKind == JsonValueKind.String
                    ? dependency.Value.GetString() ?? string.Empty
                    : string.Empty;

                dependencies.Add(new DependencyRef(dependency.Name, range));
            }
        }

        dependencies = dependencies.OrderBy(d => d.Id, StringComparer.OrdinalIgnoreCase).ToList();

        bool isDirect = direct is not null && direct.Contains(id);
        return new ResolvedPackage(id, packageVersion, isDirect, dependencies);
    }
}

using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;

namespace DepRisk.Data.Npm;

/// <summary>
/// Reads the resolved dependency graph from an npm <c>package-lock.json</c> (lockfileVersion 2 or 3: the <c>packages</c> map).
/// The input is untrusted: the parser is bounded (JSON depth), never executes anything, validates every name that ends up
/// in a result, and reports problems as <see cref="InvalidInputException"/>. See ADR 0010.
/// </summary>
/// <remarks>
/// What the <c>packages</c> map contains, and how it is read:
/// <list type="bullet">
/// <item>Key <c>""</c> is the project itself: its name and what it asks for (dependencies, devDependencies,
/// optionalDependencies, peerDependencies). Required.</item>
/// <item>Keys <c>node_modules/x</c> and <c>node_modules/a/node_modules/x</c> are installed packages. The same package can
/// be installed several times, at different versions, in different places; every installed instance is one entry here and
/// its <c>Path</c> is the key.</item>
/// <item>Keys without a <c>node_modules</c> segment (other than <c>""</c>) are first-party code in the repository (workspace
/// members, <c>file:</c> directories): they are not packages to look up in advisories, but what they ask for counts as
/// "direct". Entries with <c>link: true</c> point to such code and are skipped.</item>
/// <item>If an entry has a <c>name</c>, that is the package's real name (an alias install, <c>"foo": "npm:bar@1"</c>, has
/// the key <c>node_modules/foo</c> and the name <c>bar</c>); advisories are about the real name.</item>
/// </list>
/// Not read: the legacy <c>dependencies</c> tree of lockfileVersion 2 (the <c>packages</c> map has the same information),
/// <c>dev</c>/<c>optional</c>/<c>peer</c> flags (a finding in a development dependency is still a finding), and where a
/// package was downloaded from (<c>resolved</c>): a package from a git URL or a local tarball is matched by name and version
/// like a registry package (ADR 0010, known limits).
/// </remarks>
public static class NpmLockParser
{
    /// <summary>npm has no target frameworks: the whole lock file is one target.</summary>
    public const string TargetName = "npm";

    private const string NodeModules = "node_modules/";
    private const int MaxNameLength = 214;
    private const int MaxVersionLength = 256;
    private const int MaxRangeLength = 1000;

    private static readonly int[] SupportedLockfileVersions = [2, 3];

    // A lock file written by npm 7+ for lockfileVersion 2 also repeats the tree in the legacy "dependencies" section, which
    // nests one level per node_modules level (two JSON levels each), so the limit is higher than for the other inputs.
    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 128,
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
    };

    private static readonly string[] OwnerDependencyFields =
        ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

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
                || !root.TryGetProperty("lockfileVersion", out JsonElement versionElement)
                || versionElement.ValueKind != JsonValueKind.Number
                || !versionElement.TryGetInt32(out int lockfileVersion))
            {
                throw new InvalidInputException($"{displayPath}: not an npm lock file (missing 'lockfileVersion').");
            }

            if (lockfileVersion == 1)
            {
                throw new InvalidInputException(
                    $"{displayPath}: lockfileVersion 1 (npm 6 and older) has no 'packages' map and is not supported. "
                    + "Run 'npm install --package-lock-only' with npm 7 or newer to upgrade the lock file.");
            }

            if (!SupportedLockfileVersions.Contains(lockfileVersion))
            {
                throw new InvalidInputException(
                    $"{displayPath}: unsupported lockfileVersion {lockfileVersion} (supported: {string.Join(", ", SupportedLockfileVersions)}). "
                    + $"Please report your npm version at {ProductInfo.RepositoryUrl}/issues.");
            }

            if (!root.TryGetProperty("packages", out JsonElement packagesElement) || packagesElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidInputException($"{displayPath}: the lock file has no 'packages' object.");
            }

            List<KeyValuePair<string, JsonElement>> entries = ReadEntries(packagesElement, displayPath);

            if (!entries.Any(e => e.Key.Length == 0))
            {
                throw new InvalidInputException($"{displayPath}: the lock file has no root entry (key \"\") in 'packages'.");
            }

            Owners owners = ReadOwners(entries, displayPath);
            string projectName = ReadProjectName(entries, root) ?? fallbackProjectName;

            List<ResolvedPackage> packages = [];

            foreach ((string key, JsonElement entry) in entries)
            {
                ResolvedPackage? package = ReadPackage(key, entry, owners, displayPath);

                if (package is not null)
                {
                    packages.Add(package);
                }
            }

            packages = packages
                .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.Version, StringComparer.Ordinal)
                .ThenBy(p => p.Path, StringComparer.Ordinal)
                .ToList();

            // The project file (package.json) is derived by the caller from where the lock file lives.
            return new ProjectGraph(projectName, displayPath, [new TargetGraph(TargetName, packages)]);
        }
    }

    private static List<KeyValuePair<string, JsonElement>> ReadEntries(JsonElement packages, string displayPath)
    {
        List<KeyValuePair<string, JsonElement>> entries = [];
        HashSet<string> seen = new(StringComparer.Ordinal);

        foreach (JsonProperty property in packages.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                throw new InvalidInputException($"{displayPath}: duplicate key '{SafeText.Clean(property.Name, 100)}' in 'packages'.");
            }

            if (property.Value.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidInputException($"{displayPath}: the entry '{SafeText.Clean(property.Name, 100)}' in 'packages' is not an object.");
            }

            entries.Add(new KeyValuePair<string, JsonElement>(property.Name, property.Value));
        }

        return entries;
    }

    /// <summary>
    /// What the project itself and its first-party members (workspaces) ask for. <c>ByScope</c> maps an owner's scope (""
    /// for the project, the lock key such as "packages/web" for a member) to name and constraint; <c>Any</c> is the union, root
    /// first and then members in key order, for packages hoisted to the project's top level on behalf of a member.
    /// </summary>
    private sealed record Owners(Dictionary<string, Dictionary<string, string>> ByScope, Dictionary<string, string> Any)
    {
        /// <summary>The constraint that makes a package at <paramref name="scope"/> direct, or null if nothing asks for it there.</summary>
        public string? Requested(string scope, string name)
        {
            if (!ByScope.ContainsKey(scope))
            {
                return null;
            }

            if (ByScope[scope].TryGetValue(name, out string? own))
            {
                return own;
            }

            // Top level of the project: a workspace member's dependency is installed there too (hoisting).
            return scope.Length == 0 && Any.TryGetValue(name, out string? hoisted) ? hoisted : null;
        }
    }

    private static Owners ReadOwners(List<KeyValuePair<string, JsonElement>> entries, string displayPath)
    {
        Dictionary<string, Dictionary<string, string>> byScope = new(StringComparer.Ordinal);
        Dictionary<string, string> any = new(StringComparer.Ordinal);

        // Root first, then first-party members in key order, so the constraint recorded for a name is deterministic.
        IEnumerable<KeyValuePair<string, JsonElement>> owners = entries
            .Where(e => e.Key.Length == 0 || IsFirstParty(e.Key, e.Value))
            .OrderBy(e => e.Key.Length == 0 ? 0 : 1)
            .ThenBy(e => e.Key, StringComparer.Ordinal);

        foreach ((string key, JsonElement entry) in owners)
        {
            Dictionary<string, string> own = new(StringComparer.Ordinal);
            HashSet<string> optionalPeers = ReadOptionalPeers(entry);

            foreach (string field in OwnerDependencyFields)
            {
                foreach ((string name, string range) in ReadNameRangePairs(entry, field, key, displayPath))
                {
                    // An optional peer is "works with", not "asks for": it does not make the package a direct dependency.
                    if (field == "peerDependencies" && optionalPeers.Contains(name))
                    {
                        continue;
                    }

                    own.TryAdd(name, range);
                    any.TryAdd(name, range);
                }
            }

            byScope[key] = own;
        }

        return new Owners(byScope, any);
    }

    /// <summary>First-party code: an entry without a node_modules segment that is not a link. Links only point to such code.</summary>
    private static bool IsFirstParty(string key, JsonElement entry) =>
        key.Length > 0
        && !key.Contains(NodeModules, StringComparison.Ordinal)
        && !IsLink(entry);

    private static bool IsLink(JsonElement entry) =>
        entry.TryGetProperty("link", out JsonElement link) && link.ValueKind == JsonValueKind.True;

    private static string? ReadProjectName(List<KeyValuePair<string, JsonElement>> entries, JsonElement root)
    {
        JsonElement rootEntry = entries.First(e => e.Key.Length == 0).Value;

        foreach (JsonElement source in new[] { rootEntry, root })
        {
            if (source.TryGetProperty("name", out JsonElement name)
                && name.ValueKind == JsonValueKind.String
                && name.GetString() is { Length: > 0 and <= MaxNameLength } text
                && !text.Any(char.IsControl))
            {
                return text;
            }
        }

        return null;
    }

    private static ResolvedPackage? ReadPackage(string key, JsonElement entry, Owners owners, string displayPath)
    {
        // The project itself, first-party code, and links to first-party code are not packages.
        if (key.Length == 0 || IsLink(entry) || !key.Contains(NodeModules, StringComparison.Ordinal))
        {
            return null;
        }

        int lastSegment = key.LastIndexOf(NodeModules, StringComparison.Ordinal);
        string scope = lastSegment == 0 ? string.Empty : key[..(lastSegment - 1)];
        string keyName = key[(lastSegment + NodeModules.Length)..];

        if (lastSegment > 0 && key[lastSegment - 1] != '/')
        {
            throw new InvalidInputException($"{displayPath}: unexpected package key '{SafeText.Clean(key, 100)}'.");
        }

        RequireValidName(keyName, key, displayPath);

        string id = keyName;

        if (entry.TryGetProperty("name", out JsonElement nameElement))
        {
            if (nameElement.ValueKind != JsonValueKind.String || nameElement.GetString() is not { } realName)
            {
                throw new InvalidInputException($"{displayPath}: the 'name' of '{SafeText.Clean(key, 100)}' is not a string.");
            }

            RequireValidName(realName, key, displayPath);
            id = realName;
        }

        if (!entry.TryGetProperty("version", out JsonElement versionElement)
            || versionElement.ValueKind != JsonValueKind.String
            || versionElement.GetString() is not { Length: > 0 and <= MaxVersionLength } version
            || version.Any(char.IsControl))
        {
            throw new InvalidInputException($"{displayPath}: the entry '{SafeText.Clean(key, 100)}' has no valid 'version'.");
        }

        // Direct: the project (or a workspace member) asks for it, and it is installed at the top level of the project or
        // of a member (not inside another package's node_modules).
        string? requested = owners.Requested(scope, keyName);
        bool isDirect = requested is not null;

        return new ResolvedPackage(id, version, isDirect, ReadDependencies(entry, key, displayPath), requested, key);
    }

    /// <summary>
    /// What an installed package asks for: dependencies, optionalDependencies, and peerDependencies that are not marked
    /// optional in peerDependenciesMeta (npm 7+ installs those). The first field that names a package wins.
    /// </summary>
    private static List<DependencyRef> ReadDependencies(JsonElement entry, string key, string displayPath)
    {
        Dictionary<string, string> byName = new(StringComparer.Ordinal);

        foreach ((string name, string range) in ReadNameRangePairs(entry, "dependencies", key, displayPath))
        {
            byName.TryAdd(name, range);
        }

        foreach ((string name, string range) in ReadNameRangePairs(entry, "optionalDependencies", key, displayPath))
        {
            byName.TryAdd(name, range);
        }

        HashSet<string> optionalPeers = ReadOptionalPeers(entry);

        foreach ((string name, string range) in ReadNameRangePairs(entry, "peerDependencies", key, displayPath))
        {
            if (!optionalPeers.Contains(name))
            {
                byName.TryAdd(name, range);
            }
        }

        return byName
            .Select(pair => new DependencyRef(pair.Key, pair.Value))
            .OrderBy(d => d.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(d => d.Id, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Names of peer dependencies that peerDependenciesMeta marks optional.</summary>
    private static HashSet<string> ReadOptionalPeers(JsonElement entry)
    {
        HashSet<string> optionalPeers = new(StringComparer.Ordinal);

        if (entry.TryGetProperty("peerDependenciesMeta", out JsonElement meta) && meta.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty peer in meta.EnumerateObject())
            {
                if (peer.Value.ValueKind == JsonValueKind.Object
                    && peer.Value.TryGetProperty("optional", out JsonElement optional)
                    && optional.ValueKind == JsonValueKind.True)
                {
                    optionalPeers.Add(peer.Name);
                }
            }
        }

        return optionalPeers;
    }

    private static IEnumerable<(string Name, string Range)> ReadNameRangePairs(JsonElement entry, string field, string key, string displayPath)
    {
        if (!entry.TryGetProperty(field, out JsonElement element) || element.ValueKind != JsonValueKind.Object)
        {
            yield break;
        }

        foreach (JsonProperty property in element.EnumerateObject())
        {
            RequireValidName(property.Name, key, displayPath);

            string range = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() ?? string.Empty : string.Empty;

            if (range.Length > MaxRangeLength || range.Any(char.IsControl))
            {
                throw new InvalidInputException(
                    $"{displayPath}: '{SafeText.Clean(key.Length == 0 ? "(project)" : key, 100)}' has an invalid version constraint for '{SafeText.Clean(property.Name, 100)}'.");
            }

            yield return (property.Name, range);
        }
    }

    private static void RequireValidName(string name, string key, string displayPath)
    {
        if (!IsValidPackageName(name))
        {
            throw new InvalidInputException(
                $"{displayPath}: '{SafeText.Clean(key.Length == 0 ? "(project)" : key, 100)}' contains the invalid package name '{SafeText.Clean(name, 100)}'.");
        }
    }

    /// <summary>
    /// npm package names: optionally scoped (<c>@scope/name</c>), at most 214 characters, made of the characters that URL
    /// encoding leaves alone (letters, digits, <c>- _ . ! ~ * ' ( )</c>; old packages may use upper case). Anything else
    /// in a lock file is not a package name npm could have written, so it is rejected rather than copied into results.
    /// </summary>
    public static bool IsValidPackageName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxNameLength)
        {
            return false;
        }

        string[] parts = name.StartsWith('@') ? name[1..].Split('/') : [name];

        if (name.StartsWith('@') ? parts.Length != 2 : parts.Length != 1)
        {
            return false;
        }

        return parts.All(part => part.Length > 0 && part != "." && part != ".." && part.All(IsNameChar));
    }

    private static bool IsNameChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '!' or '~' or '*' or '\'' or '(' or ')';
}

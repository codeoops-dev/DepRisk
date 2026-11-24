using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.Npm;

namespace DepRisk.Data.Sbom;

/// <summary>
/// Reads the components of a CycloneDX (JSON, specVersion 1.2 to 1.7) or SPDX (JSON, 2.2 and 2.3) SBOM into the dependency model, so
/// that a scan, a match or a rank can start from an SBOM as it does from a lock file. See ADR 0029.
/// The input is untrusted: the parser is bounded (JSON depth), never executes anything, validates every name that ends up in a
/// result, drops purl qualifiers, and reports problems as <see cref="InvalidInputException"/>.
/// </summary>
/// <remarks>
/// What is read: components with a Package URL of type <c>nuget</c> or <c>npm</c>. Components without a purl and of other types
/// are not read (DepRisk matches NuGet and npm advisories). The root (CycloneDX <c>metadata.component</c>, the elements an SPDX
/// document describes) is the project, not a dependency. One scan reads one ecosystem: with both in the SBOM, the caller chooses.
/// Direct or transitive comes from the relationships: a component is direct when the root depends on it (CycloneDX
/// <c>dependencies</c>; SPDX <c>DEPENDS_ON</c> and the <c>*_DEPENDENCY_OF</c> types). An SBOM that records no relationships, or no
/// root, is refused: "direct" decides policy results and VEX statements, and it cannot be known from a flat list.
/// An SBOM records neither version ranges nor install paths, so the graph has neither (the <c>graph</c> command refuses it).
/// The version of a component is the one in its purl; the <c>version</c> field is used only when the purl has none.
/// </remarks>
public static class SbomParser
{
    /// <summary>The version recorded for a component that has none: it is counted as skipped and never matched.</summary>
    public const string UnknownVersion = NpmLockParser.UnresolvedVersion;

    private const int MaxIdLength = 256;
    private const int MaxVersionLength = 256;
    private const int MaxProjectNameLength = 255;

    private static readonly string[] CycloneDxVersions = ["1.2", "1.3", "1.4", "1.5", "1.6", "1.7"];
    private static readonly string[] SpdxVersions = ["SPDX-2.2", "SPDX-2.3"];

    // "A <type> B" means A depends on B.
    private static readonly string[] SpdxForward = ["DEPENDS_ON"];

    // "A <type> B" means B depends on A.
    private static readonly string[] SpdxReverse =
    [
        "DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF",
        "RUNTIME_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF",
    ];

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 64,
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
    };

    /// <summary>The file names read as an SBOM without being asked: <c>bom.json</c>, <c>sbom.json</c>, <c>*.cdx.json</c> and <c>*.spdx.json</c>.</summary>
    public static bool IsSbomFileName(string fileName) =>
        fileName.Equals("bom.json", StringComparison.OrdinalIgnoreCase)
        || fileName.Equals("sbom.json", StringComparison.OrdinalIgnoreCase)
        || fileName.EndsWith(".cdx.json", StringComparison.OrdinalIgnoreCase)
        || fileName.EndsWith(".spdx.json", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the text is a JSON object with a CycloneDX <c>bomFormat</c> or an SPDX <c>spdxVersion</c>. Never throws.</summary>
    public static bool LooksLikeSbom(string json)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(json, DocumentOptions);
            JsonElement root = document.RootElement;

            return root.ValueKind == JsonValueKind.Object
                && ((root.TryGetProperty("bomFormat", out JsonElement format) && format.ValueKind == JsonValueKind.String)
                    || (root.TryGetProperty("spdxVersion", out JsonElement version) && version.ValueKind == JsonValueKind.String));
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <param name="requested">The ecosystem to read; null reads the one the SBOM has, and asks for a choice when it has both.</param>
    public static (Ecosystem Ecosystem, ProjectGraph Graph) Parse(string json, string displayPath, string fallbackProjectName, Ecosystem? requested)
    {
        ArgumentNullException.ThrowIfNull(json);
        ArgumentNullException.ThrowIfNull(fallbackProjectName);

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

            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidInputException($"{displayPath}: not a CycloneDX or SPDX JSON document.");
            }

            Sbom sbom;

            if (root.TryGetProperty("bomFormat", out JsonElement bomFormat) && bomFormat.ValueKind == JsonValueKind.String)
            {
                sbom = ReadCycloneDx(root, bomFormat.GetString(), displayPath);
            }
            else if (root.TryGetProperty("spdxVersion", out JsonElement spdxVersion) && spdxVersion.ValueKind == JsonValueKind.String)
            {
                sbom = ReadSpdx(root, spdxVersion.GetString(), displayPath);
            }
            else
            {
                throw new InvalidInputException($"{displayPath}: not a CycloneDX or SPDX JSON document (no 'bomFormat' and no 'spdxVersion').");
            }

            Ecosystem ecosystem = ChooseEcosystem(sbom, requested, displayPath);
            return (ecosystem, BuildGraph(sbom, ecosystem, displayPath, fallbackProjectName));
        }
    }

    // ---- the common shape both formats are read into ----

    private sealed record Component(string Ref, Ecosystem Ecosystem, string Id, string Version);

    private sealed class Sbom
    {
        public string? Name { get; init; }

        public List<Component> Components { get; } = [];

        /// <summary>The elements that stand for the project itself (CycloneDX metadata.component; what an SPDX document describes).</summary>
        public HashSet<string> Roots { get; } = new(StringComparer.Ordinal);

        /// <summary>Who depends on whom, by reference.</summary>
        public Dictionary<string, HashSet<string>> Edges { get; } = new(StringComparer.Ordinal);

        /// <summary>The roots that have an entry in the relationships (CycloneDX: a dependencies entry for the root).</summary>
        public bool RootHasEntry { get; set; }

        public bool HasEdges => Edges.Values.Any(targets => targets.Count > 0);

        public void AddEdge(string from, string to)
        {
            if (!Edges.TryGetValue(from, out HashSet<string>? targets))
            {
                targets = new HashSet<string>(StringComparer.Ordinal);
                Edges[from] = targets;
            }

            if (from != to)
            {
                targets.Add(to);
            }
        }
    }

    // ---- CycloneDX ----

    private static Sbom ReadCycloneDx(JsonElement root, string? format, string displayPath)
    {
        if (format != "CycloneDX")
        {
            throw new InvalidInputException($"{displayPath}: unsupported 'bomFormat' '{SafeText.Clean(format, 40)}'.");
        }

        string? specVersion = root.TryGetProperty("specVersion", out JsonElement spec) && spec.ValueKind == JsonValueKind.String ? spec.GetString() : null;

        if (specVersion is null || !CycloneDxVersions.Contains(specVersion, StringComparer.Ordinal))
        {
            throw new InvalidInputException(
                $"{displayPath}: unsupported CycloneDX specVersion '{SafeText.Clean(specVersion ?? "(none)", 40)}' (supported: {string.Join(", ", CycloneDxVersions)}).");
        }

        string? name = null;
        string? rootRef = null;

        if (root.TryGetProperty("metadata", out JsonElement metadata)
            && metadata.ValueKind == JsonValueKind.Object
            && metadata.TryGetProperty("component", out JsonElement rootComponent)
            && rootComponent.ValueKind == JsonValueKind.Object)
        {
            name = StringProperty(rootComponent, "name");
            rootRef = StringProperty(rootComponent, "bom-ref");
        }

        Sbom sbom = new() { Name = name };

        if (rootRef is not null)
        {
            sbom.Roots.Add(rootRef);
        }

        // Components can be nested (a component's own components). Walked with a stack, so the depth of the file cannot exhaust ours.
        int anonymous = 0;
        Stack<JsonElement> pending = new();

        if (root.TryGetProperty("components", out JsonElement components) && components.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in components.EnumerateArray())
            {
                pending.Push(item);
            }
        }

        while (pending.Count > 0)
        {
            JsonElement component = pending.Pop();

            if (component.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (component.TryGetProperty("components", out JsonElement nested) && nested.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in nested.EnumerateArray())
                {
                    pending.Push(item);
                }
            }

            string reference = StringProperty(component, "bom-ref") ?? "#" + (++anonymous).ToString(System.Globalization.CultureInfo.InvariantCulture);

            if (TryReadComponent(reference, StringProperty(component, "purl"), StringProperty(component, "version"), displayPath, out Component? read))
            {
                sbom.Components.Add(read!);
            }
        }

        if (root.TryGetProperty("dependencies", out JsonElement dependencies) && dependencies.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement entry in dependencies.EnumerateArray())
            {
                string? reference = entry.ValueKind == JsonValueKind.Object ? StringProperty(entry, "ref") : null;

                if (reference is null)
                {
                    continue;
                }

                if (rootRef is not null && reference == rootRef)
                {
                    sbom.RootHasEntry = true;
                }

                if (entry.TryGetProperty("dependsOn", out JsonElement dependsOn) && dependsOn.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement target in dependsOn.EnumerateArray())
                    {
                        if (target.ValueKind == JsonValueKind.String && target.GetString() is { Length: > 0 } to)
                        {
                            sbom.AddEdge(reference, to);
                        }
                    }
                }
            }
        }

        return sbom;
    }

    // ---- SPDX 2.x ----

    private static Sbom ReadSpdx(JsonElement root, string? version, string displayPath)
    {
        if (version is null || !SpdxVersions.Contains(version, StringComparer.Ordinal))
        {
            throw new InvalidInputException(
                $"{displayPath}: unsupported SPDX version '{SafeText.Clean(version ?? "(none)", 40)}' (supported: {string.Join(", ", SpdxVersions)}; SPDX 3 is not read).");
        }

        string? documentId = StringProperty(root, "SPDXID");
        Sbom sbom = new() { Name = StringProperty(root, "name") };

        if (root.TryGetProperty("documentDescribes", out JsonElement describes) && describes.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in describes.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } id)
                {
                    sbom.Roots.Add(id);
                }
            }
        }

        if (root.TryGetProperty("relationships", out JsonElement relationships) && relationships.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement relationship in relationships.EnumerateArray())
            {
                if (relationship.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string? from = StringProperty(relationship, "spdxElementId");
                string? to = StringProperty(relationship, "relatedSpdxElement");
                string? type = StringProperty(relationship, "relationshipType");

                if (from is null || to is null || type is null)
                {
                    continue;
                }

                if (SpdxForward.Contains(type, StringComparer.Ordinal))
                {
                    sbom.AddEdge(from, to);
                }
                else if (SpdxReverse.Contains(type, StringComparer.Ordinal))
                {
                    sbom.AddEdge(to, from);
                }
                else if (type == "DESCRIBES" && documentId is not null && from == documentId)
                {
                    sbom.Roots.Add(to);
                }
                else if (type == "DESCRIBED_BY" && documentId is not null && to == documentId)
                {
                    sbom.Roots.Add(from);
                }
            }
        }

        // SPDX has no entry for the root as such: what the document describes has relationships, or it does not.
        sbom.RootHasEntry = sbom.Roots.Any(sbom.Edges.ContainsKey);

        if (root.TryGetProperty("packages", out JsonElement packages) && packages.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement package in packages.EnumerateArray())
            {
                if (package.ValueKind != JsonValueKind.Object || StringProperty(package, "SPDXID") is not { } id)
                {
                    continue;
                }

                string? purl = null;

                if (package.TryGetProperty("externalRefs", out JsonElement references) && references.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement reference in references.EnumerateArray())
                    {
                        if (reference.ValueKind == JsonValueKind.Object
                            && StringProperty(reference, "referenceCategory") is "PACKAGE-MANAGER" or "PACKAGE_MANAGER"
                            && StringProperty(reference, "referenceType") == "purl")
                        {
                            purl = StringProperty(reference, "referenceLocator");
                            break;
                        }
                    }
                }

                if (TryReadComponent(id, purl, StringProperty(package, "versionInfo"), displayPath, out Component? read))
                {
                    sbom.Components.Add(read!);
                }
            }
        }

        return sbom;
    }

    // ---- components ----

    /// <summary>
    /// A component that has a NuGet or npm purl. Null for no purl and for other types (they are not read); an error for a text that
    /// is not a purl, and for a NuGet or npm purl whose name or version is not one the package manager could have written.
    /// </summary>
    private static bool TryReadComponent(string reference, string? purlText, string? declaredVersion, string displayPath, out Component? component)
    {
        component = null;

        if (purlText is null)
        {
            return false;
        }

        if (!PackageUrl.TryParse(purlText, out PackageUrl? purl) || purl is null)
        {
            throw new InvalidInputException($"{displayPath}: '{SafeText.Clean(purlText, 100)}' is not a package URL.");
        }

        Ecosystem? ecosystem = purl.Type switch
        {
            "nuget" => Ecosystem.NuGet,
            "npm" => Ecosystem.Npm,
            _ => null,
        };

        if (ecosystem is null)
        {
            return false;
        }

        string id = purl.Namespace is null ? purl.Name : purl.Namespace + "/" + purl.Name;
        bool validId = ecosystem == Ecosystem.Npm
            ? NpmLockParser.IsValidPackageName(id)
            : purl.Namespace is null && id.Length is > 0 and <= MaxIdLength && !id.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '/' or '\\');

        if (!validId)
        {
            throw new InvalidInputException($"{displayPath}: the package URL '{SafeText.Clean(purlText, 100)}' has an invalid {ecosystem.DisplayName} package name.");
        }

        string? version = purl.Version ?? declaredVersion;

        if (version is not null && (version.Length > MaxVersionLength || version.Any(c => char.IsControl(c) || char.IsWhiteSpace(c))))
        {
            throw new InvalidInputException($"{displayPath}: the package URL '{SafeText.Clean(purlText, 100)}' has an invalid version.");
        }

        component = new Component(reference, ecosystem, id, string.IsNullOrEmpty(version) ? UnknownVersion : UrlCredentials.Mask(version));
        return true;
    }

    private static Ecosystem ChooseEcosystem(Sbom sbom, Ecosystem? requested, string displayPath)
    {
        // The root is the project, not a dependency, whatever its purl says.
        List<Ecosystem> present = sbom.Components
            .Where(c => !sbom.Roots.Contains(c.Ref))
            .Select(c => c.Ecosystem)
            .Distinct()
            .ToList();

        if (requested is not null)
        {
            if (!present.Contains(requested))
            {
                throw new InvalidInputException($"{displayPath}: the SBOM has no {requested.DisplayName} components (components with a package URL of type {requested.Id}).");
            }

            return requested;
        }

        return present.Count switch
        {
            0 => throw new InvalidInputException($"{displayPath}: the SBOM has no NuGet or npm components (components with a package URL of type nuget or npm)."),
            1 => present[0],
            _ => throw new InvalidInputException($"{displayPath}: the SBOM has both NuGet and npm components. Choose one with --ecosystem nuget or --ecosystem npm."),
        };
    }

    private static ProjectGraph BuildGraph(Sbom sbom, Ecosystem ecosystem, string displayPath, string fallbackProjectName)
    {
        List<Component> components = sbom.Components.Where(c => c.Ecosystem == ecosystem && !sbom.Roots.Contains(c.Ref)).ToList();

        // Direct or transitive is known only from the relationships, and they must be there (see the class remarks).
        if (sbom.Roots.Count == 0)
        {
            throw new InvalidInputException(
                $"{displayPath}: the SBOM does not say which component is the project (CycloneDX metadata.component, SPDX documentDescribes), "
                + "so direct and transitive dependencies cannot be told apart. Generate it with the root component.");
        }

        if (!sbom.HasEdges || !sbom.RootHasEntry)
        {
            throw new InvalidInputException(
                $"{displayPath}: the SBOM records no dependency relationships of the project (CycloneDX dependencies, SPDX DEPENDS_ON or *_DEPENDENCY_OF), "
                + "so direct and transitive dependencies cannot be told apart. Generate it with its dependency graph.");
        }

        Dictionary<string, Component> byRef = new(StringComparer.Ordinal);

        foreach (Component component in components)
        {
            byRef.TryAdd(component.Ref, component);
        }

        HashSet<string> direct = new(StringComparer.Ordinal);

        foreach (string rootRef in sbom.Roots)
        {
            if (sbom.Edges.TryGetValue(rootRef, out HashSet<string>? targets))
            {
                foreach (string target in targets)
                {
                    if (byRef.TryGetValue(target, out Component? found))
                    {
                        direct.Add(Key(found));
                    }
                }
            }
        }

        // One package per id and version: the same component can appear under several parents.
        Dictionary<string, (Component Component, HashSet<string> Dependencies)> packages = new(StringComparer.Ordinal);

        foreach (Component component in components)
        {
            string key = Key(component);

            if (!packages.TryGetValue(key, out (Component Component, HashSet<string> Dependencies) existing))
            {
                existing = (component, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                packages[key] = existing;
            }

            if (sbom.Edges.TryGetValue(component.Ref, out HashSet<string>? edges))
            {
                foreach (string edge in edges)
                {
                    if (byRef.TryGetValue(edge, out Component? target) && Key(target) != key)
                    {
                        existing.Dependencies.Add(target.Id);
                    }
                }
            }
        }

        List<ResolvedPackage> resolved = packages
            .Values
            .Select(p => new ResolvedPackage(
                p.Component.Id,
                p.Component.Version,
                direct.Contains(Key(p.Component)),
                p.Dependencies.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).Select(d => new DependencyRef(d, string.Empty)).ToList()))
            .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Id, StringComparer.Ordinal)
            .ThenBy(p => p.Version, StringComparer.Ordinal)
            .ToList();

        string name = sbom.Name is { Length: > 0 and <= MaxProjectNameLength } text && !text.Any(char.IsControl) ? text : fallbackProjectName;
        return new ProjectGraph(name, displayPath, [new TargetGraph("sbom", resolved)]);
    }

    private static string Key(Component component) => component.Id + "@" + component.Version;

    private static string? StringProperty(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } text ? text : null;
}

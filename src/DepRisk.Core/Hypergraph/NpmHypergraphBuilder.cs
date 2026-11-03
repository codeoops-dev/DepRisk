using DepRisk.Core.Model;
using DepRisk.Core.Versioning;

namespace DepRisk.Core.Hypergraph;

/// <summary>
/// Builds the dependency hypergraph of an npm lock file. Differences from NuGet (ADR 0011): the same package can be installed
/// several times, so a node is an installed instance (identified by its lock path), and what a package requires is resolved
/// the way Node does it: look in the package's own <c>node_modules</c>, then in each enclosing directory's, up to the top.
/// Ranges are node-semver; a range that is not understood, or a requirement nothing resolves, is undecided, never satisfied.
/// </summary>
public static class NpmHypergraphBuilder
{
    private const string NodeModules = "node_modules";

    public static TargetHypergraph BuildTarget(string projectName, TargetGraph target)
    {
        ArgumentNullException.ThrowIfNull(projectName);
        ArgumentNullException.ThrowIfNull(target);

        // Packages without a path cannot be placed in the tree; every npm package has one (the parser sets it).
        List<ResolvedPackage> packages = target.Packages.Where(p => p.Path is not null).ToList();
        Dictionary<string, ResolvedPackage> byPath = new(StringComparer.Ordinal);

        foreach (ResolvedPackage package in packages)
        {
            byPath[package.Path!] = package;
        }

        List<HypergraphNode> nodes = packages
            .Select(p => new HypergraphNode(p.Id, p.Version, p.IsDirect, p.Requested, p.Path))
            .OrderBy(n => n.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(n => n.Version, StringComparer.Ordinal)
            .ThenBy(n => n.Path, StringComparer.Ordinal)
            .ToList();

        List<Hyperedge> edges = [];

        // The project hyperedge: what the project (and its workspace members) asked for, checked against what is installed
        // at the place that satisfies the ask.
        List<ResolvedPackage> direct = packages
            .Where(p => p.IsDirect)
            .OrderBy(p => KeyName(p.Path!), StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Path, StringComparer.Ordinal)
            .ToList();

        if (direct.Count > 0)
        {
            edges.Add(MakeEdge(
                $"project:{projectName}",
                "project",
                projectName,
                path: null,
                direct.Select(p => (KeyName(p.Path!), p.Requested, (ResolvedPackage?)p))));
        }

        foreach (ResolvedPackage package in packages
                     .Where(p => p.Dependencies.Count > 0)
                     .OrderBy(p => p.Path, StringComparer.Ordinal))
        {
            edges.Add(MakeEdge(
                package.Path!,
                "package",
                $"{package.Id}@{package.Version}",
                package.Path,
                package.Dependencies.Select(d => (d.Id, (string?)d.Range, Resolve(package.Path!, d.Id, byPath)))));
        }

        return new TargetHypergraph(target.Name, nodes, edges, HypergraphBuilder.Stats(nodes, edges));
    }

    /// <summary>
    /// Node's lookup: from the directory of the requirer, try <c>&lt;dir&gt;/node_modules/&lt;name&gt;</c>, then do the same for
    /// each parent directory, skipping directories that are themselves named node_modules. Null if nothing is installed there.
    /// </summary>
    public static ResolvedPackage? Resolve(string requirerPath, string name, IReadOnlyDictionary<string, ResolvedPackage> byPath)
    {
        string directory = requirerPath;

        while (true)
        {
            if (directory != NodeModules && !directory.EndsWith("/" + NodeModules, StringComparison.Ordinal))
            {
                string candidate = directory.Length == 0 ? $"{NodeModules}/{name}" : $"{directory}/{NodeModules}/{name}";

                if (byPath.TryGetValue(candidate, out ResolvedPackage? found))
                {
                    return found;
                }
            }

            if (directory.Length == 0)
            {
                return null;
            }

            int slash = directory.LastIndexOf('/');
            directory = slash < 0 ? string.Empty : directory[..slash];
        }
    }

    /// <summary>The name a package is installed under: the part of its path after the last node_modules segment (the alias for an alias install).</summary>
    private static string KeyName(string path)
    {
        int index = path.LastIndexOf(NodeModules + "/", StringComparison.Ordinal);
        return index < 0 ? path : path[(index + NodeModules.Length + 1)..];
    }

    private static Hyperedge MakeEdge(
        string id,
        string kind,
        string owner,
        string? path,
        IEnumerable<(string Package, string? Range, ResolvedPackage? Found)> requires)
    {
        List<Requirement> requirements = requires
            .OrderBy(r => r.Package, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Found?.Path, StringComparer.Ordinal)
            .Select(r => Check(r.Package, r.Range, r.Found))
            .ToList();

        List<string> scope = [kind == "package" ? owner[..owner.LastIndexOf('@')] : owner];
        scope.AddRange(requirements.Select(r => r.Package));

        bool? satisfied = requirements.Any(r => r.Satisfied == false)
            ? false
            : requirements.Any(r => r.Satisfied is null) ? null : true;

        return new Hyperedge(id, kind, owner, scope, requirements, satisfied, path);
    }

    private static Requirement Check(string package, string? range, ResolvedPackage? found)
    {
        if (found is null)
        {
            return new Requirement(package, range, null, null);
        }

        if (!Ecosystem.Npm.TryParseVersion(found.Version, out NuGetVersion? version)
            || version is null
            || !NpmVersionRange.TryParseSpec(range, out NpmVersionRange? parsed)
            || parsed is null)
        {
            return new Requirement(package, range, found.Version, null, found.Path);
        }

        return new Requirement(package, range, found.Version, parsed.Contains(version), found.Path);
    }
}

using DepRisk.Core.Model;
using DepRisk.Core.Versioning;

namespace DepRisk.Core.Hypergraph;

/// <summary>
/// Builds the dependency hypergraph of a resolved scan: one node per resolved package, one hyperedge per package version
/// that requires something (scope: the package and everything it requires), and one project hyperedge (the project and its
/// direct dependencies). Every requirement is checked against the resolved version, which exposes constraints that the
/// resolved set violates (NuGet reports these as warning NU1608) and requirements it cannot decide.
/// This is the structure the remediation optimizer and the verification kernel work on (docs/method.md sections 1 and 6).
/// </summary>
public static class HypergraphBuilder
{
    public static HypergraphResult Build(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);

        List<ProjectHypergraph> projects = scan.Projects
            .Select(p => new ProjectHypergraph(
                p.Name,
                p.ProjectFile,
                p.Targets.Select(t => scan.Ecosystem == Ecosystem.Npm.Id ? NpmHypergraphBuilder.BuildTarget(p.Name, t) : BuildTarget(p.Name, t)).ToList()))
            .ToList();

        return new HypergraphResult(HypergraphResult.CurrentSchemaVersion, scan.Tool, scan.Ecosystem, projects);
    }

    /// <summary>Builds the hypergraph of one NuGet target. For npm see <see cref="NpmHypergraphBuilder"/>; <see cref="Build"/> picks by ecosystem.</summary>
    public static TargetHypergraph BuildTarget(string projectName, TargetGraph target)
    {
        ArgumentNullException.ThrowIfNull(projectName);
        ArgumentNullException.ThrowIfNull(target);

        Dictionary<string, ResolvedPackage> resolved = new(StringComparer.OrdinalIgnoreCase);

        foreach (ResolvedPackage package in target.Packages)
        {
            resolved[package.Id] = package;
        }

        List<HypergraphNode> nodes = target.Packages
            .Select(p => new HypergraphNode(p.Id, p.Version, p.IsDirect, p.Requested))
            .OrderBy(n => n.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(n => n.Version, StringComparer.Ordinal)
            .ToList();

        List<Hyperedge> edges = [];

        List<ResolvedPackage> direct = target.Packages
            .Where(p => p.IsDirect)
            .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (direct.Count > 0)
        {
            edges.Add(MakeEdge(
                $"project:{projectName}",
                "project",
                projectName,
                direct.Select(p => (p.Id, p.Requested)),
                resolved));
        }

        foreach (ResolvedPackage package in target.Packages
                     .Where(p => p.Dependencies.Count > 0)
                     .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(p => p.Version, StringComparer.Ordinal))
        {
            edges.Add(MakeEdge(
                $"{package.Id}@{package.Version}",
                "package",
                $"{package.Id}@{package.Version}",
                package.Dependencies.Select(d => (d.Id, (string?)d.Range)),
                resolved));
        }

        return new TargetHypergraph(target.Name, nodes, edges, Stats(nodes, edges));
    }

    private static Hyperedge MakeEdge(
        string id,
        string kind,
        string owner,
        IEnumerable<(string Package, string? Range)> requires,
        Dictionary<string, ResolvedPackage> resolved)
    {
        List<Requirement> requirements = requires
            .OrderBy(r => r.Package, StringComparer.OrdinalIgnoreCase)
            .Select(r => Check(r.Package, r.Range, resolved))
            .ToList();

        // The scope is the package ids the hyperedge constrains: for a package hyperedge that includes the owner's own id.
        List<string> scope = [];

        if (kind == "package")
        {
            scope.Add(owner[..owner.LastIndexOf('@')]);
        }
        else
        {
            scope.Add(owner);
        }

        scope.AddRange(requirements.Select(r => r.Package));

        bool? satisfied = requirements.Any(r => r.Satisfied == false)
            ? false
            : requirements.Any(r => r.Satisfied is null) ? null : true;

        return new Hyperedge(id, kind, owner, scope, requirements, satisfied);
    }

    private static Requirement Check(string package, string? range, Dictionary<string, ResolvedPackage> resolved)
    {
        if (!resolved.TryGetValue(package, out ResolvedPackage? found))
        {
            return new Requirement(package, range, null, null);
        }

        if (!NuGetVersion.TryParse(found.Version, out NuGetVersion? version)
            || version is null
            || !NuGetVersionRange.TryParse(range, out NuGetVersionRange? parsed)
            || parsed is null)
        {
            return new Requirement(package, range, found.Version, null);
        }

        return new Requirement(package, range, found.Version, parsed.Contains(version));
    }

    internal static HypergraphStats Stats(List<HypergraphNode> nodes, List<Hyperedge> edges)
    {
        IEnumerable<Requirement> all = edges.SelectMany(e => e.Requires);
        int shared = edges
            .SelectMany(e => e.Requires.Select(r => r.ResolvedPath ?? r.Package).Distinct(StringComparer.OrdinalIgnoreCase))
            .GroupBy(p => p, StringComparer.OrdinalIgnoreCase)
            .Count(g => g.Count() >= 2);

        return new HypergraphStats(
            nodes.Count,
            nodes.Count(n => n.IsDirect),
            edges.Count,
            edges.Count == 0 ? 0 : edges.Max(e => e.Arity),
            edges.Sum(e => e.Requires.Count),
            all.Count(r => r.Satisfied == false),
            all.Count(r => r.Satisfied is null),
            shared);
    }
}

namespace DepRisk.Core.Hypergraph;

/// <summary>
/// A package at the version the project resolved to. <c>Path</c> identifies the installed instance when a package can be
/// installed several times (npm: the lock file key); null for NuGet.
/// </summary>
public sealed record HypergraphNode(string Id, string Version, bool IsDirect, string? Requested, string? Path = null);

/// <summary>
/// One requirement inside a hyperedge: the owner needs <c>Package</c> to be within <c>Range</c> (as declared).
/// <c>Resolved</c> is the version the project actually resolved to, if any.
/// <c>Satisfied</c>: true, false (the resolved version is outside the declared range), or null when it cannot be decided
/// (the package is not in the resolved graph, or the range is not understood). Never guessed.
/// <c>ResolvedPath</c> is the installed instance the requirement was resolved to (npm: found by Node's lookup, walking up
/// the <c>node_modules</c> directories from the requirer); null for NuGet and for requirements that could not be resolved.
/// </summary>
public sealed record Requirement(string Package, string? Range, string? Resolved, bool? Satisfied, string? ResolvedPath = null);

/// <summary>
/// A hyperedge <c>e = (S_e, C_e)</c> of docs/method.md section 1: <c>Scope</c> is the set of packages it constrains, and its
/// constraint is "if the owner is at its resolved version, every requirement holds". <c>Kind</c> is "package" (a package
/// version and what it requires) or "project" (the project and what it asked for directly).
/// <c>Satisfied</c> is false if any requirement is violated, null if none is violated but some cannot be decided, else true.
/// <c>Path</c> is the installed instance that owns a package hyperedge (npm); null for NuGet and for the project hyperedge.
/// </summary>
public sealed record Hyperedge(
    string Id,
    string Kind,
    string Owner,
    IReadOnlyList<string> Scope,
    IReadOnlyList<Requirement> Requires,
    bool? Satisfied,
    string? Path = null)
{
    /// <summary>The number of packages the hyperedge constrains. Pairwise dependencies would all have arity 2.</summary>
    public int Arity => Scope.Count;
}

public sealed record HypergraphStats(
    int Nodes,
    int DirectNodes,
    int Hyperedges,
    int MaxArity,
    int Requirements,
    int Violated,
    int Unresolved,
    int SharedRequirements);

public sealed record TargetHypergraph(
    string Name,
    IReadOnlyList<HypergraphNode> Nodes,
    IReadOnlyList<Hyperedge> Hyperedges,
    HypergraphStats Stats);

public sealed record ProjectHypergraph(string Name, string? ProjectFile, IReadOnlyList<TargetHypergraph> Targets);

/// <summary>Result of <c>deprisk graph</c>. Public contract: schemas/graph.v1.schema.json. Deterministic.</summary>
public sealed record HypergraphResult(
    int SchemaVersion,
    Model.ToolInfo Tool,
    string Ecosystem,
    IReadOnlyList<ProjectHypergraph> Projects)
{
    public const int CurrentSchemaVersion = 1;
}

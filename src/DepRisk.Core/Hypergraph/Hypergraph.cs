namespace DepRisk.Core.Hypergraph;

/// <summary>A package at the version the project resolved to.</summary>
public sealed record HypergraphNode(string Id, string Version, bool IsDirect, string? Requested);

/// <summary>
/// One requirement inside a hyperedge: the owner needs <c>Package</c> to be within <c>Range</c> (as declared).
/// <c>Resolved</c> is the version the project actually resolved to, if any.
/// <c>Satisfied</c>: true, false (the resolved version is outside the declared range), or null when it cannot be decided
/// (the package is not in the resolved graph, or the range is not understood). Never guessed.
/// </summary>
public sealed record Requirement(string Package, string? Range, string? Resolved, bool? Satisfied);

/// <summary>
/// A hyperedge <c>e = (S_e, C_e)</c> of docs/method.md section 1: <c>Scope</c> is the set of packages it constrains, and its
/// constraint is "if the owner is at its resolved version, every requirement holds". <c>Kind</c> is "package" (a package
/// version and what it requires) or "project" (the project and what it asked for directly).
/// <c>Satisfied</c> is false if any requirement is violated, null if none is violated but some cannot be decided, else true.
/// </summary>
public sealed record Hyperedge(
    string Id,
    string Kind,
    string Owner,
    IReadOnlyList<string> Scope,
    IReadOnlyList<Requirement> Requires,
    bool? Satisfied)
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

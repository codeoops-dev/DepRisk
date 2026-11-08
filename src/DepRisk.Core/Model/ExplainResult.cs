namespace DepRisk.Core.Model;

/// <summary>Where a finding stands and why, in words that can be checked against the data next to them.</summary>
public sealed record ExplainPosition(string Method, int Rank, int Of, int? BaselineRank, IReadOnlyList<string> Why);

/// <summary>
/// One finding explained: the finding as ranked (signals, reachability summary, risk), the full reachability verdict with its path
/// (when reachability was analyzed), its position, the evidence behind the verdict as plain sentences, and what would change it.
/// </summary>
public sealed record ExplainFinding(
    RankedFinding Finding,
    ReachVerdict? Reachability,
    ExplainPosition Position,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> WhatWouldChange);

/// <summary>Result of <c>deprisk explain</c>. Public contract: schemas/explain.v1.schema.json. Deterministic: no timestamps, no absolute paths.</summary>
public sealed record ExplainResult(
    int SchemaVersion,
    ToolInfo Tool,
    string Ecosystem,
    string Method,
    string Query,
    IReadOnlyList<ExplainFinding> Findings)
{
    public const int CurrentSchemaVersion = 1;
}

using DepRisk.Core;
using DepRisk.Core.Hypergraph;
using DepRisk.Core.Model;

namespace DepRisk.Data.Hypergraph;

/// <summary>A hypergraph result plus the digest of everything read to produce it.</summary>
public sealed record HypergraphOutcome(HypergraphResult Result, string InputsDigest);

/// <summary>Scans a path for the restored dependency graph and builds its hypergraph.</summary>
public static class HypergraphService
{
    /// <param name="ecosystem">The ecosystem to read; null detects it from the files found.</param>
    public static HypergraphOutcome Build(string scanPath, ToolInfo tool, Ecosystem? ecosystem = null)
    {
        ArgumentNullException.ThrowIfNull(scanPath);
        ArgumentNullException.ThrowIfNull(tool);

        ScanOutcome scan = ScanService.ScanDetailed(scanPath, tool, ecosystem);

        return new HypergraphOutcome(HypergraphBuilder.Build(scan.Result), scan.InputsDigest);
    }
}

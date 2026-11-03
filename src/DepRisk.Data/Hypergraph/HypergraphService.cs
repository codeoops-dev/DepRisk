using DepRisk.Core;
using DepRisk.Core.Hypergraph;
using DepRisk.Core.Model;

namespace DepRisk.Data.Hypergraph;

/// <summary>A hypergraph result plus the digest of everything read to produce it.</summary>
public sealed record HypergraphOutcome(HypergraphResult Result, string InputsDigest);

/// <summary>Scans a path for the restored dependency graph and builds its hypergraph.</summary>
public static class HypergraphService
{
    /// <param name="ecosystem">The ecosystem to read; null detects it. Only NuGet has a hypergraph so far.</param>
    public static HypergraphOutcome Build(string scanPath, ToolInfo tool, Ecosystem? ecosystem = null)
    {
        ArgumentNullException.ThrowIfNull(scanPath);
        ArgumentNullException.ThrowIfNull(tool);

        ScanOutcome scan = ScanService.ScanDetailed(scanPath, tool, ecosystem);

        // npm needs path-based resolution (the same package can be installed at several versions) and node-semver ranges:
        // that is the next slice. Say so instead of producing a graph that would be wrong.
        if (scan.Result.Ecosystem != Ecosystem.NuGet.Id)
        {
            throw new InvalidInputException(
                $"'graph' supports NuGet projects only for now; the dependency hypergraph for {Ecosystem.FromId(scan.Result.Ecosystem).DisplayName} is planned. "
                + "Use --ecosystem nuget to read the NuGet projects here.");
        }

        return new HypergraphOutcome(HypergraphBuilder.Build(scan.Result), scan.InputsDigest);
    }
}

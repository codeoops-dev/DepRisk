using System.Text.Json;
using DepRisk.Core.Hypergraph;

namespace DepRisk.Data.Hypergraph;

/// <summary>Canonical JSON for <see cref="HypergraphResult"/>.</summary>
public static class HypergraphResultJson
{
    public static string Serialize(HypergraphResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, OutputJson.Options) + "\n";
    }
}

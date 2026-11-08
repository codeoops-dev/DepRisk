using System.Text.Json;
using DepRisk.Core.Bench;

namespace DepRisk.Data.Bench;

/// <summary>Canonical JSON for <see cref="BenchResult"/> (schemas/bench-result.v1.schema.json).</summary>
public static class BenchResultJson
{
    public static string Serialize(BenchResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, OutputJson.Options) + "\n";
    }
}

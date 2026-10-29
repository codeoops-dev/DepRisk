using System.Text.Json;
using DepRisk.Core.Model;

namespace DepRisk.Data;

/// <summary>Canonical JSON for <see cref="RankingResult"/>.</summary>
public static class RankingResultJson
{
    public static string Serialize(RankingResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, OutputJson.Options) + "\n";
    }
}

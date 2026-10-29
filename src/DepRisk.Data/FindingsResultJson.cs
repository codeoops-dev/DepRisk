using System.Text.Json;
using DepRisk.Core.Model;

namespace DepRisk.Data;

/// <summary>Canonical JSON for <see cref="FindingsResult"/>.</summary>
public static class FindingsResultJson
{
    public static string Serialize(FindingsResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, OutputJson.Options) + "\n";
    }
}

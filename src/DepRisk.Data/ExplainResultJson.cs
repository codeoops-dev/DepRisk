using System.Text.Json;
using DepRisk.Core.Model;

namespace DepRisk.Data;

/// <summary>Canonical JSON for <see cref="ExplainResult"/>.</summary>
public static class ExplainResultJson
{
    public static string Serialize(ExplainResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, OutputJson.Options) + "\n";
    }
}

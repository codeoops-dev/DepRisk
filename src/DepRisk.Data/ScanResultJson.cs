using System.Text.Json;
using DepRisk.Core.Model;

namespace DepRisk.Data;

/// <summary>Canonical JSON for <see cref="ScanResult"/>.</summary>
public static class ScanResultJson
{
    public static string Serialize(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, OutputJson.Options) + "\n";
    }
}

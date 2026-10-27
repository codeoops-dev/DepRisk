using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using DepRisk.Core.Model;

namespace DepRisk.Data;

/// <summary>Canonical JSON for <see cref="ScanResult"/>: camelCase, indented, LF line endings, no escaping surprises.</summary>
public static class ScanResultJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        NewLine = "\n",
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,

        // The output is a data file, not HTML: keep ranges such as ">= 1.0.0" readable.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Serialize(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, Options) + "\n";
    }
}

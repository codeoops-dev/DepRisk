using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DepRisk.Data;

/// <summary>The JSON style of every DepRisk result file: camelCase, indented, LF line endings, readable ranges.</summary>
internal static class OutputJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        NewLine = "\n",
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,

        // The output is a data file, not HTML: keep ranges such as ">= 1.0.0" readable.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}

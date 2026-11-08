using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using DepRisk.Core.Risk;

namespace DepRisk.Data.Risk;

/// <summary>
/// Writes a complete parameters file (schemas/risk-params.v1.schema.json): every number, not only the ones that changed, so that the file
/// stays valid and means the same when a later version of the tool ships other defaults. <c>provenance</c> says where the numbers come
/// from; the model ignores it and it is not part of the parameters digest.
/// </summary>
public static class RiskParametersWriter
{
    public const int MaxProvenanceLength = 600;

    public static string Write(RiskParameters parameters, string provenance)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(provenance);

        if (parameters.Validate() is { } problem)
        {
            throw new InvalidOperationException($"parameters are not valid: {problem}.");
        }

        using MemoryStream stream = new();

        using (Utf8JsonWriter w = new(stream, new JsonWriterOptions { Indented = true, NewLine = "\n", Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            w.WriteStartObject();
            w.WriteNumber("schemaVersion", 1);
            w.WriteString("provenance", provenance);

            w.WriteStartObject("reach");
            Beta(w, "reachable", parameters.Reach.Reachable);
            Beta(w, "possiblyReachable", parameters.Reach.PossiblyReachable);
            Beta(w, "unknown", parameters.Reach.Unknown);
            Beta(w, "unreachable", parameters.Reach.Unreachable);
            Beta(w, "notAnalyzed", parameters.Reach.NotAnalyzed);
            w.WriteEndObject();

            ExploitParams e = parameters.Exploit;
            w.WriteStartObject("exploit");
            w.WriteNumber("epssConcentration", e.EpssConcentration);
            Beta(w, "noEpss", e.NoEpss);
            w.WriteNumber("kevMean", e.KevMean);
            w.WriteNumber("ransomwareKevMean", e.RansomwareKevMean);
            w.WriteNumber("kevConcentration", e.KevConcentration);
            w.WriteEndObject();

            ImpactParams i = parameters.Impact;
            w.WriteStartObject("impact");
            w.WriteNumber("low", i.Low);
            w.WriteNumber("high", i.High);
            w.WriteNumber("lowSeverityFactor", i.LowSeverityFactor);
            w.WriteNumber("moderateSeverityFactor", i.ModerateSeverityFactor);
            w.WriteNumber("highSeverityFactor", i.HighSeverityFactor);
            w.WriteNumber("criticalSeverityFactor", i.CriticalSeverityFactor);
            w.WriteNumber("unknownSeverityLow", i.UnknownSeverityLow);
            w.WriteNumber("unknownSeverityHigh", i.UnknownSeverityHigh);
            w.WriteEndObject();

            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray()) + "\n";
    }

    private static void Beta(Utf8JsonWriter w, string name, BetaParams beta)
    {
        w.WriteStartObject(name);
        w.WriteNumber("alpha", beta.Alpha);
        w.WriteNumber("beta", beta.Beta);
        w.WriteEndObject();
    }
}

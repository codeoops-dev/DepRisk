using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Risk;

namespace DepRisk.Data.Risk;

public sealed record LoadedRiskParameters(RiskParameters Parameters, string Calibration, string ParametersDigest);

/// <summary>
/// Reads a parameters file for the risk model (schemas/risk-params.v1.schema.json): the built-in defaults with any of their numbers
/// replaced. Strict on purpose: an unknown property is an error, because a misspelled parameter that is silently ignored would run
/// the placeholder defaults while the user believes the calibrated values are in use.
/// </summary>
public static class RiskParametersLoader
{
    public const long MaxFileBytes = 1024 * 1024;
    public const string DefaultsCalibration = "uncalibrated-defaults";
    public const string CustomCalibration = "custom";

    private static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow };

    public static LoadedRiskParameters Defaults() => Describe(RiskParameters.Default, DefaultsCalibration);

    public static LoadedRiskParameters Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (!File.Exists(path))
        {
            throw new InvalidInputException($"risk parameters not found: {SafeText.Clean(path, 200)}");
        }

        string name = Path.GetFileName(path);
        byte[] bytes;

        try
        {
            if (new FileInfo(path).Length > MaxFileBytes)
            {
                throw new InvalidInputException($"{name}: larger than 1 MB; not a risk parameters file.");
            }

            bytes = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"{name}: cannot be read ({ex.Message})", ex);
        }

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(bytes, DocumentOptions);
        }
        catch (JsonException ex)
        {
            throw new InvalidInputException($"{name}: not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("schemaVersion", out JsonElement version) || !version.TryGetInt32(out int v))
            {
                throw new InvalidInputException($"{name}: not a risk parameters file (missing 'schemaVersion').");
            }

            if (v != 1)
            {
                throw new InvalidInputException($"{name}: unsupported schemaVersion {v} (this version reads 1).");
            }

            RiskParameters parameters = Apply(root, RiskParameters.Default, name);

            if (parameters.Validate() is { } problem)
            {
                throw new InvalidInputException($"{name}: {problem}.");
            }

            return Describe(parameters, CustomCalibration);
        }
    }

    private static LoadedRiskParameters Describe(RiskParameters parameters, string calibration) =>
        new(parameters, calibration, Digest.Sha256Hex(parameters.Canonical()));

    private static RiskParameters Apply(JsonElement root, RiskParameters start, string file)
    {
        RequireKnown(root, ["schemaVersion", "reach", "exploit", "impact"], "the file", file);

        RiskParameters result = start;

        if (root.TryGetProperty("reach", out JsonElement reach))
        {
            RequireObject(reach, "reach", file);
            RequireKnown(reach, ["reachable", "possiblyReachable", "unknown", "unreachable", "notAnalyzed"], "reach", file);
            ReachParams r = start.Reach;
            result = result with
            {
                Reach = new ReachParams(
                    Beta(reach, "reachable", r.Reachable, file),
                    Beta(reach, "possiblyReachable", r.PossiblyReachable, file),
                    Beta(reach, "unknown", r.Unknown, file),
                    Beta(reach, "unreachable", r.Unreachable, file),
                    Beta(reach, "notAnalyzed", r.NotAnalyzed, file)),
            };
        }

        if (root.TryGetProperty("exploit", out JsonElement exploit))
        {
            RequireObject(exploit, "exploit", file);
            RequireKnown(exploit, ["epssConcentration", "noEpss", "kevMean", "ransomwareKevMean", "kevConcentration"], "exploit", file);
            ExploitParams e = start.Exploit;
            result = result with
            {
                Exploit = new ExploitParams(
                    Number(exploit, "epssConcentration", e.EpssConcentration, "exploit", file),
                    Beta(exploit, "noEpss", e.NoEpss, file),
                    Number(exploit, "kevMean", e.KevMean, "exploit", file),
                    Number(exploit, "ransomwareKevMean", e.RansomwareKevMean, "exploit", file),
                    Number(exploit, "kevConcentration", e.KevConcentration, "exploit", file)),
            };
        }

        if (root.TryGetProperty("impact", out JsonElement impact))
        {
            RequireObject(impact, "impact", file);
            RequireKnown(
                impact,
                ["low", "high", "lowSeverityFactor", "moderateSeverityFactor", "highSeverityFactor", "criticalSeverityFactor", "unknownSeverityLow", "unknownSeverityHigh"],
                "impact",
                file);
            ImpactParams i = start.Impact;
            result = result with
            {
                Impact = new ImpactParams(
                    Number(impact, "low", i.Low, "impact", file),
                    Number(impact, "high", i.High, "impact", file),
                    Number(impact, "lowSeverityFactor", i.LowSeverityFactor, "impact", file),
                    Number(impact, "moderateSeverityFactor", i.ModerateSeverityFactor, "impact", file),
                    Number(impact, "highSeverityFactor", i.HighSeverityFactor, "impact", file),
                    Number(impact, "criticalSeverityFactor", i.CriticalSeverityFactor, "impact", file),
                    Number(impact, "unknownSeverityLow", i.UnknownSeverityLow, "impact", file),
                    Number(impact, "unknownSeverityHigh", i.UnknownSeverityHigh, "impact", file)),
            };
        }

        return result;
    }

    private static BetaParams Beta(JsonElement parent, string name, BetaParams fallback, string file)
    {
        if (!parent.TryGetProperty(name, out JsonElement element))
        {
            return fallback;
        }

        RequireObject(element, name, file);
        RequireKnown(element, ["alpha", "beta"], name, file);

        if (!element.TryGetProperty("alpha", out _) || !element.TryGetProperty("beta", out _))
        {
            throw new InvalidInputException($"{file}: '{name}' needs both 'alpha' and 'beta'.");
        }

        return new BetaParams(Number(element, "alpha", 0, name, file), Number(element, "beta", 0, name, file));
    }

    private static double Number(JsonElement parent, string name, double fallback, string section, string file)
    {
        if (!parent.TryGetProperty(name, out JsonElement element))
        {
            return fallback;
        }

        if (element.ValueKind != JsonValueKind.Number || !element.TryGetDouble(out double value))
        {
            throw new InvalidInputException($"{file}: '{section}.{name}' must be a number.");
        }

        return value;
    }

    private static void RequireObject(JsonElement element, string name, string file)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidInputException($"{file}: '{name}' must be an object.");
        }
    }

    private static void RequireKnown(JsonElement element, string[] known, string where, string file)
    {
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!known.Contains(property.Name, StringComparer.Ordinal))
            {
                throw new InvalidInputException($"{file}: unknown property '{SafeText.Clean(property.Name, 60)}' in {where} (known: {string.Join(", ", known)}).");
            }
        }
    }
}

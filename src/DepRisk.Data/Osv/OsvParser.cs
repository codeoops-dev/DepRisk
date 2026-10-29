using System.Text.Json;
using DepRisk.Core.Advisories;
using DepRisk.Core.Versioning;

namespace DepRisk.Data.Osv;

/// <summary>What happened when one OSV record was read.</summary>
public enum OsvParseStatus
{
    /// <summary>A usable advisory with at least one NuGet entry.</summary>
    Ok,

    /// <summary>The record was withdrawn by its publisher.</summary>
    Withdrawn,

    /// <summary>Valid, but it has no entry for the NuGet ecosystem (other ecosystems, or vendor ecosystems such as "Echo:NuGet").</summary>
    NotNuGet,

    /// <summary>Malformed. Skipping it could hide a vulnerability, so callers must count and report it.</summary>
    Invalid,
}

public sealed record OsvParseResult(OsvParseStatus Status, Advisory? Advisory, string? Error);

/// <summary>
/// Reads one OSV record (https://ossf.github.io/osv-schema/). Tolerant of fields it does not use, strict about the
/// fields it relies on. Input is untrusted: depth is bounded and text fields are truncated.
/// </summary>
public static class OsvParser
{
    public const int MaxSummaryLength = 500;
    public const int MaxIdLength = 200;

    private static readonly JsonDocumentOptions Options = new() { MaxDepth = 32 };

    public static OsvParseResult Parse(ReadOnlySpan<byte> utf8Json)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(utf8Json.ToArray(), Options);
        }
        catch (JsonException ex)
        {
            return Invalid($"not valid JSON ({ex.Message})");
        }

        using (document)
        {
            return Read(document.RootElement);
        }
    }

    private static OsvParseResult Read(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return Invalid("not a JSON object");
        }

        if (!TryGetString(root, "id", out string? id) || string.IsNullOrWhiteSpace(id) || id.Length > MaxIdLength)
        {
            return Invalid("missing or invalid 'id'");
        }

        bool withdrawn = root.TryGetProperty("withdrawn", out JsonElement withdrawnElement)
            && withdrawnElement.ValueKind == JsonValueKind.String;

        List<string> aliases = ReadStringArray(root, "aliases");

        string? summary = null;

        if (TryGetString(root, "summary", out string? rawSummary) && !string.IsNullOrWhiteSpace(rawSummary))
        {
            summary = rawSummary.Length > MaxSummaryLength ? rawSummary[..MaxSummaryLength] + "…" : rawSummary;
        }

        List<AdvisorySeverity> scores = [];

        if (root.TryGetProperty("severity", out JsonElement severity) && severity.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in severity.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object
                    && TryGetString(item, "type", out string? type)
                    && TryGetString(item, "score", out string? score)
                    && !string.IsNullOrEmpty(type)
                    && !string.IsNullOrEmpty(score))
                {
                    scores.Add(new AdvisorySeverity(type, score));
                }
            }
        }

        string? databaseSeverity = null;

        if (root.TryGetProperty("database_specific", out JsonElement databaseSpecific)
            && databaseSpecific.ValueKind == JsonValueKind.Object
            && TryGetString(databaseSpecific, "severity", out string? databaseSeverityText))
        {
            databaseSeverity = databaseSeverityText;
        }

        List<AffectedPackage> affected = [];

        if (root.TryGetProperty("affected", out JsonElement affectedElement) && affectedElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement entry in affectedElement.EnumerateArray())
            {
                (AffectedPackage? package, string? error) = ReadAffected(entry);

                if (error is not null)
                {
                    return Invalid($"{id}: {error}");
                }

                if (package is not null)
                {
                    affected.Add(package);
                }
            }
        }

        Advisory advisory = new(id, aliases, summary, withdrawn, scores, databaseSeverity, affected);

        if (withdrawn)
        {
            return new OsvParseResult(OsvParseStatus.Withdrawn, advisory, null);
        }

        return affected.Count == 0
            ? new OsvParseResult(OsvParseStatus.NotNuGet, advisory, null)
            : new OsvParseResult(OsvParseStatus.Ok, advisory, null);
    }

    /// <returns>(package, null) for a NuGet entry; (null, null) for an entry of another ecosystem; (null, error) if malformed.</returns>
    private static (AffectedPackage? Package, string? Error) ReadAffected(JsonElement entry)
    {
        if (entry.ValueKind != JsonValueKind.Object)
        {
            return (null, "'affected' contains a non-object entry");
        }

        if (!entry.TryGetProperty("package", out JsonElement package)
            || package.ValueKind != JsonValueKind.Object
            || !TryGetString(package, "ecosystem", out string? ecosystem)
            || !TryGetString(package, "name", out string? name)
            || string.IsNullOrWhiteSpace(name))
        {
            // Entries without a package (for example GIT-only) cannot be matched against package versions.
            return (null, null);
        }

        // Exactly "NuGet". Vendor ecosystems such as "Echo:NuGet" use their own version schemes and must not be mixed in.
        if (!string.Equals(ecosystem, "NuGet", StringComparison.OrdinalIgnoreCase))
        {
            return (null, null);
        }

        List<AffectedRange> ranges = [];

        if (entry.TryGetProperty("ranges", out JsonElement rangesElement) && rangesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement range in rangesElement.EnumerateArray())
            {
                (AffectedRange? parsed, string? error) = ReadRange(range, name);

                if (error is not null)
                {
                    return (null, error);
                }

                if (parsed is not null)
                {
                    ranges.Add(parsed);
                }
            }
        }

        List<string> versions = ReadStringArray(entry, "versions");
        return (new AffectedPackage("NuGet", name, ranges, versions), null);
    }

    private static (AffectedRange? Range, string? Error) ReadRange(JsonElement range, string packageName)
    {
        if (range.ValueKind != JsonValueKind.Object || !TryGetString(range, "type", out string? type) || string.IsNullOrEmpty(type))
        {
            return (null, $"a range of '{packageName}' has no 'type'");
        }

        bool evaluated = type.Equals("ECOSYSTEM", StringComparison.OrdinalIgnoreCase)
            || type.Equals("SEMVER", StringComparison.OrdinalIgnoreCase);

        List<RangeEvent> events = [];

        if (range.TryGetProperty("events", out JsonElement eventsElement) && eventsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in eventsElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    return (null, $"a range of '{packageName}' has a non-object event");
                }

                foreach (JsonProperty property in item.EnumerateObject())
                {
                    if (property.Value.ValueKind != JsonValueKind.String || property.Value.GetString() is not { } value)
                    {
                        return (null, $"a range of '{packageName}' has an event with a non-string value");
                    }

                    // Versions we evaluate must be understood. Anything else would silently never match.
                    if (evaluated
                        && (property.Name is "introduced" or "fixed" or "last_affected")
                        && !(property.Name == "introduced" && value == "0")
                        && !NuGetVersion.TryParse(value, out _))
                    {
                        return (null, $"'{packageName}' has the version '{value}' in a range, which is not a valid NuGet version");
                    }

                    events.Add(new RangeEvent(property.Name, value));
                }
            }
        }

        return (new AffectedRange(type, events), null);
    }

    private static List<string> ReadStringArray(JsonElement element, string name)
    {
        List<string> values = [];

        if (element.TryGetProperty(name, out JsonElement array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in array.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } text)
                {
                    values.Add(text);
                }
            }
        }

        return values;
    }

    private static bool TryGetString(JsonElement element, string name, out string? value)
    {
        value = null;

        if (element.TryGetProperty(name, out JsonElement property) && property.ValueKind == JsonValueKind.String)
        {
            value = property.GetString();
            return value is not null;
        }

        return false;
    }

    private static OsvParseResult Invalid(string error) => new(OsvParseStatus.Invalid, null, error);
}
